use crate::crypto::validate_tag;

use super::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};


fn len(auth: &Auth, properties: &Option<AuthProperties>) -> usize {
    let mut len = 2 + 1; // pkid + reason

    len += auth.response.len();

    if let Some(p) = properties {
        let properties_len = properties::len(p);
        let properties_len_len = len_len(properties_len);
        len += properties_len_len + properties_len;
    } else {
        len += 1;
    }

    len
}

pub fn read(
    fixed_header: FixedHeader,
    mut bytes: Bytes,
) -> Result<(Auth, Option<AuthProperties>), Error> {
    let variable_header_index = fixed_header.fixed_header_len;
    bytes.advance(variable_header_index);
    let pkid = read_u16(&mut bytes)?;
    let reason = read_u8(&mut bytes)?;
    let response = read_mqtt_bytes(&mut bytes)?;

    let properties = if fixed_header.remaining_len > 2 {
        Some(AuthProperties { challenge: read_mqtt_bytes(&mut bytes).ok() })
    } else { None };

    return Ok((
        Auth {
            pkid,
            reason: auth_reason_code(reason).ok_or(Error::InvalidReason(reason))?,
            response
        },
        None,
    ));
}


pub fn write(
    auth: &Auth,
    properties: &Option<AuthProperties>,
    buffer: &mut BytesMut,
) -> Result<usize, Error> {
    let len = len(auth, properties);
    buffer.put_u8(0x62);
    let count = write_remaining_length(buffer, len)?;
    buffer.put_u16(auth.pkid);
    buffer.put_u8(auth.reason as u8);

    if let Some(p) = properties {
        properties::write(p, buffer)?;
    } else {
        write_remaining_length(buffer, 0)?;
    }

    Ok(1 + count + len)
}

mod properties {
    use super::*;

    pub fn len(properties: &AuthProperties) -> usize {
        1 + properties.challenge.as_ref().map_or(0, |b| b.len())
    }

    pub fn read(mut bytes: &mut Bytes) -> Result<Option<AuthProperties>, Error> {
        let (properties_len_len, properties_len) = length(bytes.iter())?;
        bytes.advance(properties_len_len);
        if properties_len == 0 {
            return Ok(None);
        }

        let challenge = read_mqtt_bytes(bytes).ok();

        Ok(Some(AuthProperties { challenge }))
    }

    pub fn write(properties: &AuthProperties, buffer: &mut BytesMut) -> Result<(), Error> {
        let len = len(properties);
        write_remaining_length(buffer, len)?;

        if let Some(challenge) = &properties.challenge {
            write_mqtt_bytes(buffer, challenge);
        }

        Ok(())
    }
}