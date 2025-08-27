import smpplib.client
import smpplib.consts
import smpplib.gsm
import logging
import time

logging.basicConfig(level=logging.DEBUG)

# -----------------------------
# Handler DLR / deliver_sm
# -----------------------------
def handle_deliver_sm(pdu):
    logging.info("📩 DLR received:")
    logging.info(f"From: {pdu.source_addr}")
    logging.info(f"To: {pdu.destination_addr}")
    logging.info(f"Message: {pdu.short_message}")
    logging.info(f"Message ID: {pdu.message_id if hasattr(pdu, 'message_id') else 'N/A'}")
    logging.info(f"Command Status: {pdu.status}")

# -----------------------------
# Inisialisasi client
# -----------------------------
client = smpplib.client.Client('127.0.0.1', 2775)
client.set_message_received_handler(handle_deliver_sm)
client.connect()
client.bind_transceiver(system_id='test3', password='santos')

# -----------------------------
# Fungsi kirim SMS
# -----------------------------
def send_sms(source, destination, text):
    # Bagi pesan jika terlalu panjang
    parts, encoding_flag, msg_type_flag = smpplib.gsm.make_parts(text)
    
    for part in parts:
        pdu = client.send_message(
            source_addr_ton=smpplib.consts.SMPP_TON_INTL,   # numeric sender
            source_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
            source_addr=source,
            dest_addr_ton=smpplib.consts.SMPP_TON_INTL,
            dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
            destination_addr=destination,
            short_message=part,
            data_coding=encoding_flag,
            esm_class=msg_type_flag,
            registered_delivery=True,  # DLR aktif
        )
        logging.info(f"📨 Sent part, PDU seq: {pdu.sequence}")

# -----------------------------
# Kirim SMS
# -----------------------------
send_sms('12345', '628123456789', 'Test kirim kedua - 2.')

# -----------------------------
# Loop membaca DLR selama 30 detik
# -----------------------------
timeout = time.time() + 30
while time.time() < timeout:
    client.read_once()
    time.sleep(0.1)  # lebih cepat dari 1 detik agar tidak blocking

# -----------------------------
# Unbind & disconnect
# -----------------------------
client.unbind()
client.disconnect()
logging.info("Client disconnected")
