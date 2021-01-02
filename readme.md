# BSEC-Conduit Daemon
A Systemd process acting as a conduit between BSEC-Library and MQTT. It uses the Bosch Sensortec Environmental Cluster (BSEC)
fusion library to process the raw BME680 sensor readings.

Extending @TimothyBrown (2018) code to be able to sample VOC and CO2 signals.

Original @TimothyBrown code can be found at (https://github.com/timothybrown/BSEC-Conduit).

Also, originally based in @rstoermer project.
(https://github.com/rstoermer/bsec_bme680_python/)

## Main Attribution
- BSEC-Conduit:
    - @TimothyBrown (2018)
    - MIT License

## Requirements
- python-systemd
- paho.mqtt

`sudo apt-get install libsystemd-dev`
`pip3 install paho-mqtt`

## Installation
This example is to be installed into a Python venv located at `/opt/bsec` with the
user `pi` on a Raspbian distro.

- `sudo mkdir /opt/bsec` Create the directory.
- `sudo chown pi:pi /opt/bsec` Change permissions on the directory.
- `sudo -u pi git clone https://github.com/iotmx/BSEC-Conduit.git /opt/bsec` Clone the repo into our new directory.
- `sudo -u pi python3 -m venv /opt/bsec` Create our venv.
- `cd /opt/bsec` Change into the directory.
- `source bin/activate` Activate our new venv.
- `sudo -u pi pip3 install systemd-python paho-mqtt` Install required Python modules.
- `sudo python3 install.py` Run the installer.
- `sudo -u pi nano bsec-conduit.ini` Edit the config section at the top of the file. Use `CTRL-X` to save.
- `sudo systemctl start bsec-conduit.service; journalctl -f -u bsec-conduit.service` Start the program and open the log file.

## Usage
Here's a typical log output when started for the first time, stopping and subsequent runs:

`pi@raspberrypi ~# systemctl start bsec-conduit.service`
```
 systemd[1]: Starting BSEC-Conduit Daemon...
 raspberrypi BSEC-Conduit[1234]: BSEC-Conduit v0.3.3
 raspberrypi BSEC-Conduit[1234]: Generated MQTT Client ID: BME680-A12BC3D4
 raspberrypi BSEC-Conduit[1234]: Generated MQTT Base Topic: raspberrypi/BME680
 raspberrypi BSEC-Conduit[1234]: Connected to MQTT Broker.
 raspberrypi BSEC-Conduit[1234]: BSEC-Library executable or hash file not found, starting build process.
 raspberrypi BSEC-Conduit[1234]: BSEC-Library source file not found, writing file: /opt/bsec/BSEC_1.4.7.1_Generic_Release_20180907/bsec-library.c
 raspberrypi BSEC-Conduit[1234]: Detected architecture as ARMv8 64-Bit.
 raspberrypi BSEC-Conduit[1234]: Build process complete.
 raspberrypi BSEC-Conduit[1234]: Created new BSEC-Library configuration [generic_33v_3s_28d].
 raspberrypi BSEC-Conduit[1234]: Created blank BSEC-Library state file.
 raspberrypi BSEC-Conduit[1234]: BSEC-Library started.
 raspberrypi systemd[1]: Started BSEC-Conduit Daemon.
```
`pi@raspberrypi ~# systemctl stop bsec-conduit.service`
```
raspberrypi systemd[1]: Stopping BSEC-Conduit Daemon...
raspberrypi BSEC-Conduit[1234]: Caught Signal 15 (SIGTERM).
raspberrypi BSEC-Conduit[1234]: BSEC-Library stopped.
raspberrypi BSEC-Conduit[1234]: Disconnected from MQTT Broker.
systemd[1]: Stopped BSEC-Conduit Daemon.
```
`pi@raspberrypi ~# systemctl start bsec-conduit.service`
```
 systemd[1]: Starting BSEC-Conduit Daemon...
 raspberrypi BSEC-Conduit[2345]: BSEC-Conduit v0.3.3
 raspberrypi BSEC-Conduit[2345]: Generated MQTT Client ID: BME680-A12BC3D4
 raspberrypi BSEC-Conduit[2345]: Generated MQTT Base Topic: raspberrypi/BME680
 raspberrypi BSEC-Conduit[2345]: Connected to MQTT Broker.
 raspberrypi BSEC-Conduit[2345]: Found existing BSEC-Library executable, skipping build.
 raspberrypi BSEC-Conduit[2345]: Using existing BSEC-Library configuration [generic_33v_3s_28d].
 raspberrypi BSEC-Conduit[2345]: Found existing BSEC-Library state file, skipping creation.
 raspberrypi BSEC-Conduit[2345]: BSEC-Library started.
 raspberrypi systemd[1]: Started BSEC-Conduit Daemon.
```

## Version History
- v0.4.0: 2021.01.02
    - Brown's script extended to sample VOC and CO2

# BSECLibrary
Uses the Bosch BSEC sensor fusion library to retrieve and process data from a BME680 sensor.
https://www.bosch-sensortec.com/media/boschsensortec/downloads/bsec/bsec_1-4-8-0_generic_release.zip

Uses Bosch API
https://github.com/BoschSensortec/BME680_driver/releases/tag/bme680_v3.5.10

## Attribution
- BSEC-Conduit:
  - @TimothyBrown (2018)
  - Modifications by @GuillermoRamirez (2021)
  - MIT License
- bsec-library.c:
  - Code by @twartzek (2017)
  - Modifications by @TimothyBrown (2018)
  - Modifications by @GuillermoRamirez (2018)
  - MIT License
- bsec_integration.c
  - Code by Robert Bosch (2017)
  - Modifications by @GuillermoRamirez (2021)
- BSEC 1.4.8.0 Generic Release (2020):
  - Bosch Sensortec GmbH
  - Private License

## Usage

### BSECLibrary(i2c_address, temp_offset, sample_rate, voltage, retain_state, logger=None, base_dir=None)
- i2c_address: Address of the sensor.                             [0x76|0x77]
- temp_offset: An offset to add to the temperature sensor.    [10.0 to -10.0]
- sample_rate: Seconds between samples.                               [3|300]
- voltage: The voltage the sensor is run at.                        [3.3|1.8]
- retain_state: Number of days to retain the IAQ state data.           [4|28]
- logger: Logger instance to use. Use None for console output.
- base_dir: Directory to store the executable, config and state files. Must also include a sub-directory that contains an unzipped copy of the Bosch Sensortec BSEC source. Use None to automatically determine.

### BSECLibrary.open()
Call to start the underlying BSEC-Library communication process.

### BSECLibrary.close()
Call to stop the underlying BSEC-Library communication process.

### BSECLibrary.output()
Returns an iterator that you can loop over forever. Blocks between samples from the sensor. Each item is a dict() that contains the following keys:
- IAQ Accuracy
- IAQ
- Temperature
- Humidity
- Pressure
- Status
- VOCe
- CO2e

### Example
```
from bseclib import BSECLibrary

bsec_lib = BSECLibrary(0x77, 2.0, 3, 3.3, 4)
count = 0
bsec_lib.open()
for sample in bsec_lib.output():
    print(sample)
    if count == 10:
        bsec_lib.close()
        exit()
    else:
        count += 1
```
