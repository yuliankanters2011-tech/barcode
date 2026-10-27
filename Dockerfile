FROM python:3.11-slim

WORKDIR /app
COPY app.py /app/app.py

ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DB_PATH=/data/scanbase.db \
    USB_SYSFS_DEVICES=/sys/bus/usb/devices \
    USB_HID_DRIVER_DIR=/host-usbhid

EXPOSE 8080
CMD ["python3", "-u", "/app/app.py"]
