import smpplib.client
import smpplib.consts
import logging
import time

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')

# Handler untuk deliver_sm (DLR)
def handle_deliver_sm(pdu):
    """Handle deliver_sm (DLR atau incoming message)"""
    logging.info("📩 Received deliver_sm (DLR):")
    
    try:
        # Untuk smpplib, data sudah dalam format yang benar
        source_addr = pdu.source_addr.decode('utf-8') if isinstance(pdu.source_addr, bytes) else pdu.source_addr
        dest_addr = pdu.destination_addr.decode('utf-8') if isinstance(pdu.destination_addr, bytes) else pdu.destination_addr
        short_message = pdu.short_message.decode('utf-8') if isinstance(pdu.short_message, bytes) else pdu.short_message
        
        logging.info(f"  From: {source_addr}")
        logging.info(f"  To: {dest_addr}")
        logging.info(f"  Raw DLR content: {short_message}")
        
        # Parse DLR fields
        fields = {}
        for item in short_message.split():
            if ':' in item:
                key, value = item.split(':', 1)
                fields[key] = value
        
        # Extract DLR information
        msg_id = fields.get('id', 'Unknown')
        status = fields.get('stat', 'UNKNOWN')
        submit_date = fields.get('submit', '') 
        done_date = fields.get('done', '')
        
        logging.info(f"  ✅ DLR Details:")
        logging.info(f"     Message ID: {msg_id}")
        logging.info(f"     Status: {status}")
        logging.info(f"     Submit Date: {submit_date}")
        logging.info(f"     Done Date: {done_date}")
        
    except Exception as e:
        logging.error(f"❌ Error while processing deliver_sm: {e}")
        import traceback
        logging.error(traceback.format_exc())

# Konfigurasi client SMPP
client = smpplib.client.Client('127.0.0.1', 37002)  # Ganti IP dan port jika perlu

# Pasang handler
client.set_message_received_handler(handle_deliver_sm)
client.error_pdu_handler = lambda pdu: logging.warning(f"⚠️ Received error PDU: {pdu}")

# Hubungkan dan bind
client.connect()
client.bind_transceiver(system_id='dwi_test', password='123456')
logging.info("✅ Bind berhasil sebagai transceiver")

# Kirim SMS
message_text = 'Hello from Python SMPP client!'
pdu = client.send_message(
    source_addr_ton=smpplib.consts.SMPP_TON_ALNUM,
    source_addr_npi=smpplib.consts.SMPP_NPI_ISDN, 
    source_addr='YesDok',
    dest_addr_ton=1,
    dest_addr_npi=smpplib.consts.SMPP_NPI_ISDN,
    destination_addr='6289630489151',  # Ganti dengan nomor tujuan
    short_message=message_text.encode('utf-8'),
    data_coding=0,  # 0 = SMSC Default Alphabet (GSM 7-bit / ASCII)
    esm_class=0,
    registered_delivery=True,  # Penting agar DLR dikirim
)
logging.info(f"📨 SMS dikirim! PDU Sequence: {pdu.sequence}, Message ID: {getattr(pdu, 'message_id', 'N/A')}")

# Loop terima DLR
try:
    while True:
        pdu = client.read_once()
        if pdu:
            logging.debug(f"⬅️ Received PDU: {pdu}")
        time.sleep(0.5)
except KeyboardInterrupt:
    logging.info("🛑 Dihentikan oleh user")
finally:
    client.unbind()
    client.disconnect()
    logging.info("✅ Disconnected")