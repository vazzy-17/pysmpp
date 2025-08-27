
import smpplib.client
import smpplib.consts
import smpplib.gsm
import logging
import time

logging.basicConfig(level=logging.DEBUG)

def handle_deliver_sm(pdu):
    """
    Handler untuk menerima deliver_sm termasuk DLR dari Kannel
    """
    logging.info("📩 Received deliver_sm:")
    logging.info(f"From: {pdu.source_addr}")
    logging.info(f"To: {pdu.destination_addr}")
    logging.info(f"Message: {pdu.short_message}")
    logging.info(f"Command Status: {pdu.status}")
    logging.info(f"Message ID: {pdu.message_id if hasattr(pdu, 'message_id') else 'N/A'}")

    # Kirim deliver_sm_resp (otomatis dilakukan oleh smpplib)

# Inisialisasi client
client = smpplib.client.Client('127.0.0.1', 2775)

# Tambahkan handler deliver_sm
client.set_message_received_handler(handle_deliver_sm)

# Connect & bind
client.connect()
client.bind_transceiver(system_id='test3', password='santos')

# Kirim SMS
parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts('Test kirim kedua - 2.')
for part in parts:
    pdu = client.send_message(
        source_addr_ton=smpplib.consts.SMPP_TON_ALNUM,
        source_addr_npi=0,
        source_addr='YesDok',
        dest_addr_ton=1,
        dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
        destination_addr='628123456789',
        short_message=part,
        data_coding=encoding_flag,
        esm_class=msg_type_flag,
        registered_delivery=True,
    )
    logging.info(f"📨 Sent message, PDU seq: {pdu.sequence}")

# Tunggu agar bisa menerima deliver_sm
# Dalam loop, `client.read_once()` akan membaca dan memproses semua PDU masuk
timeout = time.time() + 150  # Tunggu sampai 15 detik
while time.time() < timeout:
    client.read_once()
    time.sleep(1)

# Unbind & disconnect
client.unbind()
client.disconnect()
