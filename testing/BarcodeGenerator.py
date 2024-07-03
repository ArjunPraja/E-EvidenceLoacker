import barcode
from barcode.writer import ImageWriter
from rfid.rfid import RFID

# Generate Barcode
def generate_barcode(data, barcode_type='code39'):
    # Generate barcode
    barcode_class = barcode.get_barcode_class(barcode_type)
    barcode_instance = barcode_class(data, writer=ImageWriter())
    filename = 'barcode'
    barcode_instance.save(filename)
    print(f"Barcode generated and saved as {filename}.png")

# Generate RFID
def generate_rfid(data):
    rfid = RFID(data)
    rfid.generate_image()
    rfid.show_image()

if __name__ == "__main__":
    data = input("Enter data for generating barcode and RFID: ")
    
    generate_barcode(data)
    generate_rfid(data)
