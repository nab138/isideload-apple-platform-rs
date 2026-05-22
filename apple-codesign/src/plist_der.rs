// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! Plist DER encoding. */

use {
    crate::error::AppleCodesignError,
    num_traits::cast::ToPrimitive,
    plist::Value,
    rasn::{
        AsnType, Codec, Decode, Decoder, Encode, Encoder,
        ber::de::DecodeError,
        ber::enc::EncodeError,
        de::Error as DeError,
        enc::Error as EncError,
        types::{
            Class, Constraints, Constructed, Integer, Tag,
            fields::{Field, Fields},
        },
    },
    std::collections::BTreeMap,
};

#[derive(AsnType, Debug, Decode)]
struct DictionaryEntry {
    #[rasn(tag(universal, 12))]
    key: String,
    value: WrappedValue,
}

/// Represents a plist dictionary in the rasn domain.
#[derive(Debug)]
struct Dictionary(plist::Dictionary);

impl AsnType for Dictionary {
    const TAG: Tag = Tag {
        class: Class::Context,
        value: 16,
    };
}

impl Constructed for Dictionary {
    // This is incorrect, but a required field is needed to be specified to
    // communicate to rasn it needs to know that there is fields to decode.
    const FIELDS: Fields = Fields::from_static(&[Field::new_optional_type::<()>("key")]);
}

impl Encode for Dictionary {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<(), E::Error> {
        // Sort it alphabetically.
        let map = self.0.iter().collect::<BTreeMap<_, _>>();

        encoder.encode_sequence::<Self, _>(tag, |encoder| {
            for (k, v) in map {
                let wrapped = WrappedValue::try_from(v.clone())?;

                encoder.encode_sequence::<Self, _>(Tag::SEQUENCE, |encoder| {
                    encoder.encode_utf8_string(Tag::UTF8_STRING, Constraints::NONE, k)?;
                    wrapped.encode(encoder)?;
                    Ok(())
                })?;
            }

            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Dictionary {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<Self, D::Error> {
        decoder.decode_sequence::<Self, _, _>(
            tag,
            Some(|| Self(plist::Dictionary::new())),
            |decoder| {
                let mut dict = plist::Dictionary::new();

                loop {
                    let entry = decoder.decode_optional::<DictionaryEntry>()?;

                    if let Some(entry) = entry {
                        let value = plist::Value::try_from(entry.value)?;

                        dict.insert(entry.key, value);
                    } else {
                        break;
                    }
                }

                Ok(Self(dict))
            },
        )
    }
}

/// Represents a [Value] in the rasn domain.
#[derive(AsnType, Debug, Decode, Encode)]
#[rasn(choice)]
enum WrappedValue {
    Array(Vec<WrappedValue>),
    Dictionary(Dictionary),
    #[rasn(tag(universal, 1))]
    Boolean(bool),
    #[rasn(tag(universal, 2))]
    Integer(Integer),
    #[rasn(tag(universal, 12))]
    String(String),
}

impl TryFrom<Value> for WrappedValue {
    type Error = EncodeError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Array(v) => Ok(Self::Array(
                v.into_iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Value::Dictionary(v) => Ok(Self::Dictionary(Dictionary(v))),
            Value::Boolean(v) => Ok(Self::Boolean(v)),
            Value::Integer(v) => {
                let integer = Integer::from(v.as_signed().ok_or(EncodeError::custom(
                    "could not obtain integer representation from plist integer",
                    Codec::Der,
                ))?);

                Ok(Self::Integer(integer))
            }
            Value::String(v) => Ok(Self::String(v)),
            Value::Data(_) => Err(EncodeError::custom(
                "encoding of data values not supported",
                Codec::Der,
            )),
            Value::Date(_) => Err(EncodeError::custom(
                "encoding of date values not supported",
                Codec::Der,
            )),
            Value::Real(_) => Err(EncodeError::custom(
                "encoding of real values not supported",
                Codec::Der,
            )),
            Value::Uid(_) => Err(EncodeError::custom(
                "encoding of uid values not supported",
                Codec::Der,
            )),
            _ => Err(EncodeError::custom(
                "encoding of unknown value type not supported",
                Codec::Der,
            )),
        }
    }
}

impl TryFrom<WrappedValue> for Value {
    type Error = DecodeError;

    fn try_from(value: WrappedValue) -> Result<Self, Self::Error> {
        match value {
            WrappedValue::Array(v) => Ok(Self::Array(
                v.into_iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            WrappedValue::Dictionary(v) => Ok(Self::Dictionary(v.0)),
            WrappedValue::Boolean(v) => Ok(Self::Boolean(v)),
            WrappedValue::Integer(v) => {
                let v = v.to_i64().ok_or(DecodeError::custom(
                    "could not convert BigInt to i64",
                    Codec::Der,
                ))?;

                Ok(Self::Integer(plist::Integer::from(v)))
            }
            WrappedValue::String(v) => Ok(Self::String(v)),
        }
    }
}

/// Represents a top-level plist in the rasn domain.
struct WrappedPlist(WrappedValue);

impl AsnType for WrappedPlist {
    const TAG: Tag = Tag {
        class: Class::Application,
        value: 16,
    };
}

impl Constructed for WrappedPlist {
    const FIELDS: Fields = Fields::from_static(&[
        Field::new_required_type::<Integer>("key"),
        Field::new_required_type::<WrappedValue>("value"),
    ]);
}

impl TryFrom<Value> for WrappedPlist {
    type Error = EncodeError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<WrappedPlist> for Value {
    type Error = DecodeError;

    fn try_from(value: WrappedPlist) -> Result<Self, Self::Error> {
        if let WrappedValue::Dictionary(d) = value.0 {
            Ok(Self::Dictionary(d.0))
        } else {
            Err(DecodeError::custom(
                "wrapped value not a dictionary",
                Codec::Der,
            ))
        }
    }
}

impl Encode for WrappedPlist {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<(), E::Error> {
        encoder.encode_sequence::<Self, _>(tag, |encoder| {
            encoder.encode_integer(Tag::INTEGER, Constraints::NONE, &Integer::from(1))?;
            self.0.encode(encoder)
        })?;

        Ok(())
    }
}

impl Decode for WrappedPlist {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<Self, D::Error> {
        decoder.decode_sequence::<Self, _, _>(tag, None::<fn() -> Self>, |decoder| {
            let _: Integer = decoder.decode_integer(Tag::INTEGER, Constraints::NONE)?;
            let value = WrappedValue::decode(decoder)?;

            Ok(Self(value))
        })
    }
}

/// Encode a top-level plist [Value] to DER.
pub fn der_encode_plist(value: &Value) -> Result<Vec<u8>, AppleCodesignError> {
    rasn::der::encode_scope(|encoder| {
        let wrapped = WrappedPlist::try_from(value.clone())?;
        wrapped.encode(encoder)
    })
    .map_err(|e| AppleCodesignError::PlistDer(format!("{e}")))
}

/// Decode DER to a plist [Value].
pub fn der_decode_plist(data: impl AsRef<[u8]>) -> Result<Value, AppleCodesignError> {
    rasn::der::decode::<WrappedPlist>(data.as_ref())
        .and_then(Value::try_from)
        .map_err(|e| AppleCodesignError::PlistDer(format!("{e}")))
}
