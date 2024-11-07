use crate::protocol::PubReq;

use super::*;
use bytes::{Buf, Bytes};

pub fn write(
    pubreq: &PubReq,
    buffer: &mut BytesMut,
) -> Result<usize, Error> {
    let len = {
        let mut len = 2 + "MQTT".len() // protocol name
                        + 1            // protocol version
                        + 1            // pubreq flags
                        + 2            // keep alive
                        + 1;           // no properties

        // topic and challenge len
        len += pubreq.topic.len() + 96;

        len
    };

    buffer.put_u8(0b0001_0000);
    let count = write_remaining_length(buffer, len)?;
    write_mqtt_string(buffer, "MQTT");

    buffer.put_u8(0x05);
    let flags_index = 1 + count + 2 + 4 + 1;

    write_mqtt_bytes(buffer, &pubreq.challenge_nonce);
    write_mqtt_bytes(buffer, &pubreq.topic);

    Ok(1 + count + len)
}


