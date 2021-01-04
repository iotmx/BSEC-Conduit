#!/usr/bin/env python3
"""
# BSECLibrary - (C) 2018 TimothyBrown
#   edited by iotmx 2021 Guillermo Ramirez

Uses the Bosch BSEC sensor fusion library to communicate with a BME680.



MIT License
"""
__program__ = 'BSECLibrary'
__version__ = '0.1.5'
__date__ = '2018.11.16'
__author__ = 'Timothy S. Brown'
__edited__ = 'Guillermo Ramirez'

import os
import subprocess
import logging
import platform
import time
from shutil import copy
from hashlib import md5
import json

class BSECLibraryError(Exception):
    """Base class for exceptions."""
    # Todo: Expand this into real exception handling sub-classes.
    pass

class BSECLibrary:
    """Handles communication with a BME680 using the Bosch BSEC fusion library."""

    def __init__(self, i2c_address, temp_offset, sample_rate, voltage, retain_state, logger=None, base_dir=None):
        # If the user doesn't pass a logger object, create one.
        if logger is None:
            logger = __name__
        self.log = logging.getLogger(logger)

        # Check the instance variables.
        if 119 > i2c_address < 118:
            self.log.error("Error: <i2c_address> must be one of 0x76 or 0x77.")
            raise BSECLibraryError()
        else:
            self.i2c_address = i2c_address

        if 10.0 > temp_offset < -10.0:
            self.log.error("Error: <temp_offset> must be in the range of 10.0 and -10.0.")
            raise BSECLibraryError()
        else:
            self.temp_offset = temp_offset

        if sample_rate != 3 and sample_rate != 300:
            self.log.error("Error: <sample_rate> must be one of 3 or 300.")
            raise BSECLibraryError()
        else:
            self.sample_rate = sample_rate

        if voltage != 3.3 and voltage != 1.8:
            self.log.error("Error: <voltage> must be one of 3.3 or 1.8.")
            raise BSECLibraryError()
        else:
            self.voltage = voltage

        if retain_state != 4 and retain_state != 28:
            self.log.error("Error: <retain_state> must be one of 4 or 28.")
            raise BSECLibraryError()
        else:
            self.retain_state = retain_state

        if base_dir is None:
            self.base_dir = os.getcwd()
        elif os.path.isdir(base_dir):
            self.base_dir = os.path.abspath(base_dir)
        else:
            self.log.error("Error: <base_dir> value of ({}) is not a valid directory.".format(base_dir))

        # Make sure the BSEC source directory exsists.
        src_dirs = [i for i in os.listdir(self.base_dir) if os.path.isdir(i) and 'BSEC_' in i]
        if len(src_dirs) == 0:
            self.log.error('The BSEC source directory could not be located!')
            self.log.error("Expected a directory name starting with 'BSEC_' under '{}' containing the the Bosch BSEC source files.".format(self.base_dir))
            self.log.error("Please download and unzip them from the URL below:")
            self.log.error("https://www.bosch-sensortec.com/bst/products/all_products/bsec")
            raise BSECLibraryError()
        else:
            self.src_dir = os.path.abspath(src_dirs[0])

        # Get executable, config and state file paths.
        self.exec_path = self._get_exec(self.src_dir, self.base_dir)
        self.config_path = self._get_config(self.src_dir, self.base_dir, self.config_string)
        self.state_path = self._get_state(self.base_dir)

        # Set the process variable.
        self.proc = None

    # Property function to generate the config_string variable.
    @property
    def config_string(self):
        return 'generic_{}v_{}s_{}d'.format(str(self.voltage)[0]+str(self.voltage)[2], str(self.sample_rate), str(self.retain_state))

    # Property function to generate the sample_rate_string variable.
    @property
    def sample_rate_string(self):
        return {3: 'LP', 300: 'ULP'}[self.sample_rate]

    # Function to start the bsec-library process.
    def open(self):
        if self.proc is not None:
            self.log.warning("BSEC-Library is already running!")
        else:
            new_env = os.environ.copy()
            if 'TZ' not in new_env:
                tz = int((time.timezone if (time.localtime().tm_isdst == 0) else time.altzone) / 60 / 60 * -1)
                new_env['TZ'] = 'Etc/GMT{}'.format(tz)
            run_command = [self.exec_path, str(self.i2c_address), str(self.temp_offset), self.sample_rate_string]
            self.proc = subprocess.Popen(run_command, stdout=subprocess.PIPE, env=new_env)
            if self.proc.returncode is not None:
                self.log.error('BSEC-Library encountered an error ({}) during startup.'.format(self.proc.returncode))
                raise BSECLibraryError()
            else:
                self.log.info('BSEC-Library started.')

    # Function to stop the bsec-library process.
    def close(self):
        if self.proc is None:
            self.log.warning("BSEC-Library is not running!")
        else:
            self.proc.send_signal(15)
            time.sleep(1)
            self.log.info("BSEC-Library stopped.")
            self.proc = None

    # Function to allow the user to iterate over the output.
    def output(self):
        if self.proc is not None:
            for line in iter(self.proc.stdout.readline, b''):
                data = dict(json.loads(line.decode('UTF-8')))
                if data['Status'] != '0':
                    # If there's a problem, yo we'll log it...
                    self.log.error("BSEC-Library returned error {}.".format(data['Status']))
                    # ...kill the process and hope that resolves it! (Ice, ice, baby.)
                    raise BSECLibraryError()
                else:
                    yield data
            self.log.warning("BSEC-Library ran out of data to yield!")
        else:
            self.log.warning("No data to to parse! Have you started the BSEC-Library process?")
            return None

    # Private function to build the executable. Returns the executable path.
    def _get_exec(self, src_dir, base_dir):
        def arch():
            # Make sure we're running under Linux.
            system = platform.system()
            if system != 'Linux':
                self.log.error("This library requires Linux: Got {} as our OS.".format(system))
                raise BSECLibraryError()
            # Try to detect if we're running on an ARM processor.
            machine = platform.machine()
            if 'arm' not in machine:
                self.log.error("This library requires an ARM processor: Got {} as our architecture.".format(machine))
                raise BSECLibraryError()
            # Now that we know we're on an ARM machine, try to detect if we're on a Pi.
            # This is required because platform.machine() will return ARMv7 even for ARMv8 (3B, 3B+) machines.
            rpi_processor = None
            try:
                with open('/proc/cpuinfo') as f:
                    for line in f:
                        if line.startswith('Revision'):
                            code = int(line.split(':', 1)[1].strip()[1:], 16)
                            if bool(code >> 23 & 0x000000001):
                                rpi_processor = {0: 'BCM2835', 1: 'BCM2836', 2: 'BCM2837'}[code >> 12 & 0b00000000000000001111]
                            else:
                                rpi_processor = 'BCM2835'
            except FileNotFoundError:
                pass
            if rpi_processor is not None:
                # If we are, test to see if we're on a ARMv8 machine.
                if rpi_processor is 'BCM2837':
                    self.log.info('Detected architecture as ARMv8 64-Bit.')
                    return 'Normal_version/RaspberryPI/PiThree_ArmV8-a-64bits'
                # Then test for ARMv7.
                elif rpi_processor is 'BCM2836':
                    self.log.info('Detected architecture as ARMv7 32-Bit.')
                    return 'Normal_version/RaspberryPI/PiZero_ArmV6-32bits'
                # Finally test for ARMv6.
                elif rpi_processor is 'BCM2835':
                    self.log.info('Detected architecture as ARMv6 32-Bit.')
                    # next line modified for Wisp running on Raspberry Pi Zero
                    return 'normal_version/bin/RaspberryPi/PiThree_ArmV6'
            # Well, I guess we're not on a Pi... Let's take a stab at it anyway!
            # Note: The underlying `RaspberryPI/Pi*` libraries will work on non-Pi
            # systems, as long as it's an ARM processor running Linux.
            else:
                # Test for ARMv8.
                if 'armv8' in machine:
                    self.log.info('Detected architecture as ARMv8 64-Bit.')
                    return 'Normal_version/RaspberryPI/PiThree_ArmV8-a-64bits'
                # Then we must be on a 32-Bit platform.
                else:
                    self.log.info('Detected architecture as ARM{} 32-Bit.'.format(machine[3:]))
                    return 'Normal_version/RaspberryPI/PiZero_ArmV6-32bits'
            # Catch all in case something went wrong.
            self.log.error("Encountered an unknown error trying to determine system architecture.")
            raise BSECLibraryError()

        # Build the executable if needed.
        exec_dst = '{}/bsec-library'.format(base_dir)
        build_flag = True
        if os.path.isfile(exec_dst) and os.path.isfile('{}.md5'.format(exec_dst)):
            with open(exec_dst, 'rb') as f:
                source_hash = md5(f.read()).hexdigest().strip()
            with open('{}.md5'.format(exec_dst), 'rt') as f:
                target_hash = f.read().strip()
            if target_hash == source_hash:
                build_flag = False
                self.log.info('Found existing BSEC-Library executable, skipping build.')
            else:
                self.log.warning("BSEC-Library executable and hash file don't match, rebuilding.")
        else:
            self.log.warning('BSEC-Library executable or hash file not found, starting build process.')

        # Force to rebuild (for debugging) 
        self.log.warning('Forcing build')
        build_flag = True
 
        if build_flag:
            # See if we need to write the source file.
            if not os.path.isfile('{}/bsec-library.c'.format(src_dir)):
                self.log.warning("BSEC-Library source file not found, writing file: {}/bsec-library.c".format(src_dir))
                with open('{}/bsec-library.c'.format(src_dir), 'wb') as f:
                    f.write(bsec_library_c.encode('UTF-8'))

            # See if we need to write the source file.
            self.log.warning("Writing BSEC integration source file: {}/examples/bsec_iot_example/bsec_integration.c".format(src_dir))
            with open('{}/examples/bsec_iot_example/bsec_integration.c'.format(src_dir), 'wb') as f:
                f.write(bsec_integration_c.encode('UTF-8'))

            lib_arch = arch()
            # Generate the build command.
            build_command = [
                            'cc',
                            '-Wall',
                            '-Wno-unused-but-set-variable',
                            '-Wno-unused-variable',
                            '-static',
                            '-iquote{}/BME680_driver-bme680_v3.5.10'.format(base_dir),
                            '-iquote{}/algo/{}'.format(src_dir, lib_arch),
                            '-iquote{}/examples/bsec_iot_example'.format(src_dir),
                            '{}/BME680_driver-bme680_v3.5.10/bme680.c'.format(base_dir),
                            '{}/examples/bsec_iot_example/bsec_integration.c'.format(src_dir),
                            '{}/bsec-library.c'.format(src_dir),
                            '-L{}/algo/{}'.format(src_dir, lib_arch),
                            '-lalgobsec',
                            '-lm',
                            '-lrt',
                            '-o',
                            exec_dst
                            ]
            # Run the build process.
            build_process = subprocess.run(build_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            # Check for errors.
            if build_process.returncode != 0:
                build_error = build_process.stdout.decode()
                self.log.error('Encountered an error during the build process!')
                self.log.error(build_error)
                raise BSECLibraryError()
            else:
                self.log.info("Build process complete.")

            # Write an MD5SUM of the executable.
            with open(exec_dst, 'rb') as f:
                exec_md5 = md5(f.read()).hexdigest()
            with open('{}.md5'.format(exec_dst), 'wt') as f:
                f.write(exec_md5)

        return exec_dst

    # Private function to copy the config file. Returns the config file path.
    def _get_config(self, src_dir, base_dir, config):

        config_dst = '{}/bsec-library.config'.format(base_dir)
        config_hash_table = {
            '305c5398b0359f7956584a7a52bb48ea': {'string': 'generic_18v_300s_28d', 'voltage': 1.8, 'sample rate': 300, 'retain state': 28},
            'eecd6e4000afa21901bb28e182a75c6e': {'string': 'generic_18v_300s_4d', 'voltage': 1.8, 'sample rate': 300, 'retain state': 4},
            '19389190311bbdbf3432791eb9a258b7': {'string': 'generic_18v_3s_28d', 'voltage': 1.8, 'sample rate': 3, 'retain state': 28},
            '0505f6120e216f19987b59dc011fc609': {'string': 'generic_18v_3s_4d', 'voltage': 1.8, 'sample rate': 3, 'retain state': 4},
            '344ff63b9f11c0427d7d205242ffd606': {'string': 'generic_33v_300s_28d', 'voltage': 3.3, 'sample rate': 300, 'retain state': 28},
            '16851fcb6becb9b814263deb3d31623b': {'string': 'generic_33v_300s_4d', 'voltage': 3.3, 'sample rate': 300, 'retain state': 4},
            'a401d7712179350a7b6ff6fc035d49c2': {'string': 'generic_33v_3s_28d', 'voltage': 3.3, 'sample rate': 3, 'retain state': 28},
            '1107f7ce9fcb414de64e899babc1a1ee': {'string': 'generic_33v_3s_4d', 'voltage': 3.3, 'sample rate': 3, 'retain state': 4}
            }
        try:
            with open(config_dst, 'rb') as f:
                hash = md5(f.read()).hexdigest().lower()
        except FileNotFoundError:
            hash = None

        if hash in config_hash_table and config_hash_table[hash]['string'] == config:
            self.log.info("Using existing BSEC-Library configuration [{}].".format(config))
        else:
            config_new = copy('{}/config/{}/bsec_iaq.config'.format(src_dir, config), config_dst)
            if config_new != os.path.abspath(config_dst):
                self.log.error("Error creating config file!")
                raise BSECLibraryError()
            self.log.info("Created new BSEC-Library configuration [{}].".format(config))

        return config_dst

    # Private function to create the state file if needed. Returns the state file path.
    def _get_state(self, base_dir):
        state_dst = '{}/bsec-library.state'.format(base_dir)
        try:
            open(state_dst, 'xb')
        except FileExistsError:
            self.log.info('Found existing BSEC-Library state file, skipping creation.')
        else:
            self.log.info('Created blank BSEC-Library state file.')
        return state_dst

# The C code for the BSEC-Library process itself.
bsec_library_c = """/* Copyright (C) 2017 alexh.name */
/* I2C code by twartzek 2017 */
/* argv[] code by TimothyBrown 2018 */
/* output_ready edited by iotmx 2021 Guillermo Ramirez*/
/**
  *  MIT License
  *
  *    Permission is hereby granted, free of charge, to any person obtaining a copy
  *    of this software and associated documentation files (the "Software"), to deal
  *    in the Software without restriction, including without limitation the rights
  *    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  *    copies of the Software, and to permit persons to whom the Software is
  *    furnished to do so, subject to the following conditions:
  *
  *    The above copyright notice and this permission notice shall be included in all
  *    copies or substantial portions of the Software.
  *
  *    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  *    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  *    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  *    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  *    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  *    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  *    SOFTWARE.
  */

/*
 * Read the BME680 sensor with the BSEC library by running an endless loop in
 * the bsec_iot_loop() function under Linux.
 *
 */

/* header files */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/i2c-dev.h>
#include "bsec_datatypes.h"
#include "bsec_integration.h"
#include "bme680.h"

/* definitions */
int g_i2cFid; // I2C Linux device handle
int i2c_address; // Changed from #define to argv[1].
float temp_offset; // Changed from #define to argv[2].
float sample_rate_mode; // Changed from #define to argv[3].
char *filename_state = "bsec-library.state";
char *filename_config = "bsec-library.config";

/* functions */

// open the Linux device
void i2cOpen()
{
  g_i2cFid = open("/dev/i2c-1", O_RDWR);
  if (g_i2cFid < 0) {
    perror("i2cOpen");
    exit(1);
  }
}

// close the Linux device
void i2cClose()
{
  close(g_i2cFid);
}

// set the I2C slave address for all subsequent I2C device transfers
void i2cSetAddress(int address)
{
  if (ioctl(g_i2cFid, I2C_SLAVE, address) < 0) {
    perror("i2cSetAddress");
    exit(1);
  }
}

/*
 * Write operation in either I2C or SPI
 *
 * param[in]        dev_addr        I2C or SPI device address
 * param[in]        reg_addr        register address
 * param[in]        reg_data_ptr    pointer to the data to be written
 * param[in]        data_len        number of bytes to be written
 *
 * return          result of the bus communication function
 */
int8_t bus_write(uint8_t dev_addr, uint8_t reg_addr, uint8_t *reg_data_ptr,
                 uint16_t data_len)
{
  int8_t rslt = 0; /* Return 0 for Success, non-zero for failure */

  uint8_t reg[16];
  reg[0]=reg_addr;

  for (int i=1; i<data_len+1; i++)
    reg[i] = reg_data_ptr[i-1];

  if (write(g_i2cFid, reg, data_len+1) != data_len+1) {
    perror("user_i2c_write");
    rslt = 1;
    exit(1);
  }

  return rslt;
}

/*
 * Read operation in either I2C or SPI
 *
 * param[in]        dev_addr        I2C or SPI device address
 * param[in]        reg_addr        register address
 * param[out]       reg_data_ptr    pointer to the memory to be used to store
 *                                  the read data
 * param[in]        data_len        number of bytes to be read
 *
 * return          result of the bus communication function
 */
int8_t bus_read(uint8_t dev_addr, uint8_t reg_addr, uint8_t *reg_data_ptr,
                uint16_t data_len)
{
  int8_t rslt = 0; /* Return 0 for Success, non-zero for failure */

  uint8_t reg[1];
  reg[0]=reg_addr;

  if (write(g_i2cFid, reg, 1) != 1) {
    perror("user_i2c_read_reg");
    rslt = 1;
  }

  if (read(g_i2cFid, reg_data_ptr, data_len) != data_len) {
    perror("user_i2c_read_data");
    rslt = 1;
  }

  return rslt;
}

/*
 * System specific implementation of sleep function
 *
 * param[in]       t_ms    time in milliseconds
 *
 * return          none
 */
void _sleep(uint32_t t_ms)
{
  struct timespec ts;
  ts.tv_sec = 0;
  /* mod because nsec must be in the range 0 to 999999999 */
  ts.tv_nsec = (t_ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

/*
 * Capture the system time in microseconds
 *
 * return          system_current_time    system timestamp in microseconds
 */
int64_t get_timestamp_us()
{
  struct timespec spec;
  //clock_gettime(CLOCK_REALTIME, &spec);
  /* MONOTONIC in favor of REALTIME to avoid interference by time sync. */
  clock_gettime(CLOCK_MONOTONIC, &spec);

  int64_t system_current_time_ns = (int64_t)(spec.tv_sec) * (int64_t)1000000000
                                   + (int64_t)(spec.tv_nsec);
  int64_t system_current_time_us = system_current_time_ns / 1000;

  return system_current_time_us;
}

/*
 * Handling of the ready outputs
 *
 * param[in]       timestamp       time in microseconds
 * param[in]       iaq             IAQ signal
 * param[in]       iaq_accuracy    accuracy of IAQ signal
 * param[in]       temperature     temperature signal
 * param[in]       humidity        humidity signal
 * param[in]       pressure        pressure signal
 * param[in]       raw_temperature raw temperature signal
 * param[in]       raw_humidity    raw humidity signal
 * param[in]       gas             raw gas sensor signal
 * param[in]       bsec_status     value returned by the bsec_do_steps() call
 *
 * return          none
 */
void output_ready(int64_t timestamp, float iaq, uint8_t iaq_accuracy,
                  float temperature, float humidity, float pressure,
                  float raw_temperature, float raw_humidity, float gas,
                  bsec_library_return_t bsec_status,
                  float static_iaq, float co2_equivalent,
                  float breath_voc_equivalent)
{
  //int64_t timestamp_s = timestamp / 1000000000;
  ////int64_t timestamp_ms = timestamp / 1000;

  //time_t t = timestamp_s;
  /*
   * timestamp for localtime only makes sense if get_timestamp_us() uses
   * CLOCK_REALTIME
   */
  time_t t = time(NULL);
  struct tm tm = *localtime(&t);

  printf("{\\"IAQ_Accuracy\\": \\"%d\\"", iaq_accuracy);
  printf(", \\"IAQ\\": \\"%.2f\\"", iaq);
  printf(", \\"Temperature\\": \\"%.2f\\"", temperature);
  printf(", \\"Humidity\\": \\"%.2f\\"", humidity);
  printf(", \\"Pressure\\": \\"%.2f\\"", pressure / 100);
  printf(", \\"Gas\\": \\"%.0f\\"", gas);
  printf(", \\"Status\\": \\"%d\\"", bsec_status);
  printf(", \\"IAQ_Static\\": \\"%.2f\\"", static_iaq);
  printf(", \\"CO2e\\": \\"%.2f\\"", co2_equivalent);
  printf(", \\"VOCe\\": \\"%.2f\\"}", breath_voc_equivalent);
  printf("\\r\\n");
  fflush(stdout);
}

/*
 * Load binary file from non-volatile memory into buffer
 *
 * param[in,out]   state_buffer    buffer to hold the loaded data
 * param[in]       n_buffer        size of the allocated buffer
 * param[in]       filename        name of the file on the NVM
 * param[in]       offset          offset in bytes from where to start copying
 *                                  to buffer
 * return          number of bytes copied to buffer or zero on failure
 */
uint32_t binary_load(uint8_t *b_buffer, uint32_t n_buffer, char *filename,
                     uint32_t offset)
{
  int32_t copied_bytes = 0;
  int8_t rslt = 0;

  struct stat fileinfo;
  rslt = stat(filename, &fileinfo);
  if (rslt != 0) {
    fprintf(stderr,"stat'ing binary file %s: ",filename);
    perror("");
    return 0;
  }

  uint32_t filesize = fileinfo.st_size - offset;

  if (filesize > n_buffer) {
    fprintf(stderr,"%s: %d > %d\\n", "binary data bigger than buffer", filesize,
            n_buffer);
    return 0;
  } else {
    FILE *file_ptr;
    file_ptr = fopen(filename,"rb");
    if (!file_ptr) {
      perror("fopen");
      return 0;
    }
    fseek(file_ptr,offset,SEEK_SET);
    copied_bytes = fread(b_buffer,sizeof(char),filesize,file_ptr);
    if (copied_bytes == 0) {
      fprintf(stderr,"%s empty\\n",filename);
    }
    fclose(file_ptr);
    return copied_bytes;
  }
}

/*
 * Load previous library state from non-volatile memory
 *
 * param[in,out]   state_buffer    buffer to hold the loaded state string
 * param[in]       n_buffer        size of the allocated state buffer
 *
 * return          number of bytes copied to state_buffer or zero on failure
 */
uint32_t state_load(uint8_t *state_buffer, uint32_t n_buffer)
{
  int32_t rslt = 0;
  rslt = binary_load(state_buffer, n_buffer, filename_state, 0);
  return rslt;
}

/*
 * Save library state to non-volatile memory
 *
 * param[in]       state_buffer    buffer holding the state to be stored
 * param[in]       length          length of the state string to be stored
 *
 * return          none
 */
void state_save(const uint8_t *state_buffer, uint32_t length)
{
  FILE *state_w_ptr;
  state_w_ptr = fopen(filename_state,"wb");
  fwrite(state_buffer,length,1,state_w_ptr);
  fclose(state_w_ptr);
}

/*
 * Load library config from non-volatile memory
 *
 * param[in,out]   config_buffer    buffer to hold the loaded state string
 * param[in]       n_buffer         size of the allocated state buffer
 *
 * return          number of bytes copied to config_buffer or zero on failure
 */
uint32_t config_load(uint8_t *config_buffer, uint32_t n_buffer)
{
  int32_t rslt = 0;
  /*
   * Provided config file is 4 bytes larger than buffer.
   * Apparently skipping the first 4 bytes works fine.
   *
   */
  rslt = binary_load(config_buffer, n_buffer, filename_config, 4);
  return rslt;
}

/* main */

/*
 * Main function which configures BSEC library and then reads and processes
 * the data from sensor based on timer ticks
 *
 * return      result of the processing
 */
int main(int argc, char *argv[])
{
  //putenv(DESTZONE); // Now taken care of in the Python controller.
  if (argc == 4)
    {
      i2c_address = atoi (argv[1]);
      if (i2c_address < 118 || i2c_address > 119)
        {
          printf("Error: '%s' is not a valid address for argument <i2c_address>.\\nValid Options: 118|119\\n", argv[1]);
          return 1;
        }
      temp_offset = strtof (argv[2], NULL);
      if (temp_offset > 10.0 || temp_offset < -10.0)
        {
          printf("Error: '%f' is outside of the valid range for argument <temperature_offset>.\\nValid Range: 10.0 to -10.0\\n", temp_offset);
          return 1;
        }
      if (strcmp(argv[3], "LP") == 0)
        {
          sample_rate_mode = BSEC_SAMPLE_RATE_LP;
        }
      else if (strcmp(argv[3], "ULP") == 0)
        {
          sample_rate_mode = BSEC_SAMPLE_RATE_ULP;
        }
      else
        {
          printf("Error: '%s' isn't a valid option for argument <sample_rate_mode>.\\nValid Options: LP|ULP\\n", argv[3]);
          return 1;
        }
    }
  else
    {
      printf("Usage:\\n");
      printf("  %s <i2c_address> <temp_offset> <sample_rate_mode>\\n", argv[0]);
      printf("       i2c_address: 118|119\\n       temp_offset: 10.0 to -10.0\\n  sample_rate_mode: LP|ULP\\n");
      return 1;
    }

  i2cOpen();
  i2cSetAddress(i2c_address);

  return_values_init ret;

  ret = bsec_iot_init(sample_rate_mode, temp_offset, bus_write, bus_read,
                      _sleep, state_load, config_load);
  if (ret.bme680_status) {
    /* Could not intialize BME680 */
    return (int)ret.bme680_status;
  } else if (ret.bsec_status) {
    /* Could not intialize BSEC library */
    return (int)ret.bsec_status;
  }

  /* Call to endless loop function which reads and processes data based on
   * sensor settings.
   * State is saved every 10.000 samples, which means every 10.000 * 3 secs
   * = 500 minutes (depending on the config).
   *
   */
  bsec_iot_loop(_sleep, get_timestamp_us, output_ready, state_save, 10000);

  i2cClose();
  return 0;
}
"""

bsec_integration_c = """/*
 * Copyright (C) 2017 Robert Bosch. All Rights Reserved. 
 *
 * bme680_bsec_update_subscription edited by iotmx 2021 Guillermo Ramirez
 *
 * Disclaimer
 *
 * Common:
 * Bosch Sensortec products are developed for the consumer goods industry. They may only be used
 * within the parameters of the respective valid product data sheet.  Bosch Sensortec products are
 * provided with the express understanding that there is no warranty of fitness for a particular purpose.
 * They are not fit for use in life-sustaining, safety or security sensitive systems or any system or device
 * that may lead to bodily harm or property damage if the system or device malfunctions. In addition,
 * Bosch Sensortec products are not fit for use in products which interact with motor vehicle systems.
 * The resale and/or use of products are at the purchasers own risk and his own responsibility. The
 * examination of fitness for the intended use is the sole responsibility of the Purchaser.
 *
 * The purchaser shall indemnify Bosch Sensortec from all third party claims, including any claims for
 * incidental, or consequential damages, arising from any product use not covered by the parameters of
 * the respective valid product data sheet or not approved by Bosch Sensortec and reimburse Bosch
 * Sensortec for all costs in connection with such claims.
 *
 * The purchaser must monitor the market for the purchased products, particularly with regard to
 * product safety and inform Bosch Sensortec without delay of all security relevant incidents.
 *
 * Engineering Samples are marked with an asterisk (*) or (e). Samples may vary from the valid
 * technical specifications of the product series. They are therefore not intended or fit for resale to third
 * parties or for use in end products. Their sole purpose is internal client testing. The testing of an
 * engineering sample may in no way replace the testing of a product series. Bosch Sensortec
 * assumes no liability for the use of engineering samples. By accepting the engineering samples, the
 * Purchaser agrees to indemnify Bosch Sensortec from all claims arising from the use of engineering
 * samples.
 *
 * Special:
 * This software module (hereinafter called "Software") and any information on application-sheets
 * (hereinafter called "Information") is provided free of charge for the sole purpose to support your
 * application work. The Software and Information is subject to the following terms and conditions:
 *
 * The Software is specifically designed for the exclusive use for Bosch Sensortec products by
 * personnel who have special experience and training. Do not use this Software if you do not have the
 * proper experience or training.
 *
 * This Software package is provided `` as is `` and without any expressed or implied warranties,
 * including without limitation, the implied warranties of merchantability and fitness for a particular
 * purpose.
 *
 * Bosch Sensortec and their representatives and agents deny any liability for the functional impairment
 * of this Software in terms of fitness, performance and safety. Bosch Sensortec and their
 * representatives and agents shall not be liable for any direct or indirect damages or injury, except as
 * otherwise stipulated in mandatory applicable law.
 *
 * The Information provided is believed to be accurate and reliable. Bosch Sensortec assumes no
 * responsibility for the consequences of use of such Information nor for any infringement of patents or
 * other rights of third parties which may result from its use. No license is granted by implication or
 * otherwise under any patent or patent rights of Bosch. Specifications mentioned in the Information are
 * subject to change without notice.
 *
 * It is not allowed to deliver the source code of the Software to any third party without permission of
 * Bosch Sensortec.
 *
 */

/*!
 * @file bsec_integration.c
 *
 * @brief
 * Private part of the example for using of BSEC library.
 */

/*!
 * @addtogroup bsec_examples BSEC Examples
 * @brief BSEC usage examples
 * @{*/

/**********************************************************************************************************************/
/* header files */
/**********************************************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "bsec_integration.h"

/**********************************************************************************************************************/
/* local macro definitions */
/**********************************************************************************************************************/

#define NUM_USED_OUTPUTS 10

/**********************************************************************************************************************/
/* global variable declarations */
/**********************************************************************************************************************/

/* Global sensor APIs data structure */
static struct bme680_dev bme680_g;

/* Global temperature offset to be subtracted */
static float bme680_temperature_offset_g = 0.0f;

/**********************************************************************************************************************/
/* functions */
/**********************************************************************************************************************/

/*!
 * @brief        Virtual sensor subscription
 *               Please call this function before processing of data using bsec_do_steps function
 *
 * @param[in]    sample_rate         mode to be used (either BSEC_SAMPLE_RATE_ULP or BSEC_SAMPLE_RATE_LP)
 *  
 * @return       subscription result, zero when successful
 */
static bsec_library_return_t bme680_bsec_update_subscription(float sample_rate)
{
    bsec_sensor_configuration_t requested_virtual_sensors[NUM_USED_OUTPUTS];
    uint8_t n_requested_virtual_sensors = NUM_USED_OUTPUTS;
    
    bsec_sensor_configuration_t required_sensor_settings[BSEC_MAX_PHYSICAL_SENSOR];
    uint8_t n_required_sensor_settings = BSEC_MAX_PHYSICAL_SENSOR;
    
    bsec_library_return_t status = BSEC_OK;
    
    /* note: Virtual sensors as desired to be added here */
    requested_virtual_sensors[0].sensor_id = BSEC_OUTPUT_IAQ;
    requested_virtual_sensors[0].sample_rate = sample_rate;
    requested_virtual_sensors[1].sensor_id = BSEC_OUTPUT_SENSOR_HEAT_COMPENSATED_TEMPERATURE;
    requested_virtual_sensors[1].sample_rate = sample_rate;
    requested_virtual_sensors[2].sensor_id = BSEC_OUTPUT_RAW_PRESSURE;
    requested_virtual_sensors[2].sample_rate = sample_rate;
    requested_virtual_sensors[3].sensor_id = BSEC_OUTPUT_SENSOR_HEAT_COMPENSATED_HUMIDITY;
    requested_virtual_sensors[3].sample_rate = sample_rate;
    requested_virtual_sensors[4].sensor_id = BSEC_OUTPUT_RAW_GAS;
    requested_virtual_sensors[4].sample_rate = sample_rate;
    requested_virtual_sensors[5].sensor_id = BSEC_OUTPUT_RAW_TEMPERATURE;
    requested_virtual_sensors[5].sample_rate = sample_rate;
    requested_virtual_sensors[6].sensor_id = BSEC_OUTPUT_RAW_HUMIDITY;
    requested_virtual_sensors[6].sample_rate = sample_rate;
    requested_virtual_sensors[7].sensor_id = BSEC_OUTPUT_STATIC_IAQ;
    requested_virtual_sensors[7].sample_rate = sample_rate;
    requested_virtual_sensors[8].sensor_id = BSEC_OUTPUT_CO2_EQUIVALENT;
    requested_virtual_sensors[8].sample_rate = sample_rate;
    requested_virtual_sensors[9].sensor_id = BSEC_OUTPUT_BREATH_VOC_EQUIVALENT;
    requested_virtual_sensors[9].sample_rate = sample_rate;
    
    /* Call bsec_update_subscription() to enable/disable the requested virtual sensors */
    status = bsec_update_subscription(requested_virtual_sensors, n_requested_virtual_sensors, required_sensor_settings,
        &n_required_sensor_settings);
    
    return status;
}

/*!
 * @brief       Initialize the BME680 sensor and the BSEC library
 *
 * @param[in]   sample_rate         mode to be used (either BSEC_SAMPLE_RATE_ULP or BSEC_SAMPLE_RATE_LP)
 * @param[in]   temperature_offset  device-specific temperature offset (due to self-heating)
 * @param[in]   bus_write           pointer to the bus writing function
 * @param[in]   bus_read            pointer to the bus reading function
 * @param[in]   sleep               pointer to the system specific sleep function
 * @param[in]   state_load          pointer to the system-specific state load function
 * @param[in]   config_load         pointer to the system-specific config load function
 *
 * @return      zero if successful, negative otherwise
 */
return_values_init bsec_iot_init(float sample_rate, float temperature_offset, bme680_com_fptr_t bus_write, 
                    bme680_com_fptr_t bus_read, sleep_fct sleep, state_load_fct state_load, config_load_fct config_load)
{
    return_values_init ret = {BME680_OK, BSEC_OK};
    bsec_library_return_t bsec_status = BSEC_OK;
    
    uint8_t bsec_state[BSEC_MAX_STATE_BLOB_SIZE] = {0};
    uint8_t bsec_config[BSEC_MAX_PROPERTY_BLOB_SIZE] = {0};
    uint8_t work_buffer[BSEC_MAX_WORKBUFFER_SIZE] = {0};
    int bsec_state_len, bsec_config_len;
    
    /* Fixed I2C configuration */
    bme680_g.dev_id = BME680_I2C_ADDR_PRIMARY;
    bme680_g.intf = BME680_I2C_INTF;
    /* User configurable I2C configuration */
    bme680_g.write = bus_write;
    bme680_g.read = bus_read;
    bme680_g.delay_ms = sleep;
    
    /* Initialize BME680 API */
    ret.bme680_status = bme680_init(&bme680_g);
    if (ret.bme680_status != BME680_OK)
    {
        return ret;
    }
    
    /* Initialize BSEC library */
    ret.bsec_status = bsec_init();
    if (ret.bsec_status != BSEC_OK)
    {
        return ret;
    }
    
    /* Load library config, if available */
    bsec_config_len = config_load(bsec_config, sizeof(bsec_config));
    if (bsec_config_len != 0)
    {       
        ret.bsec_status = bsec_set_configuration(bsec_config, bsec_config_len, work_buffer, sizeof(work_buffer));     
        if (ret.bsec_status != BSEC_OK)
        {
            return ret;
        }
    }
    
    /* Load previous library state, if available */
    bsec_state_len = state_load(bsec_state, sizeof(bsec_state));
    if (bsec_state_len != 0)
    {       
        ret.bsec_status = bsec_set_state(bsec_state, bsec_state_len, work_buffer, sizeof(work_buffer));     
        if (ret.bsec_status != BSEC_OK)
        {
            return ret;
        }
    }
    
    /* Set temperature offset */
    bme680_temperature_offset_g = temperature_offset;
    
    /* Call to the function which sets the library with subscription information */
    ret.bsec_status = bme680_bsec_update_subscription(sample_rate);
    if (ret.bsec_status != BSEC_OK)
    {
        return ret;
    }
    
    return ret;
}

/*!
 * @brief       Trigger the measurement based on sensor settings
 *
 * @param[in]   sensor_settings     settings of the BME680 sensor adopted by sensor control function
 * @param[in]   sleep               pointer to the system specific sleep function
 *
 * @return      none
 */
static void bme680_bsec_trigger_measurement(bsec_bme_settings_t *sensor_settings, sleep_fct sleep)
{
    uint16_t meas_period;
    uint8_t set_required_settings;
    int8_t bme680_status = BME680_OK;
        
    /* Check if a forced-mode measurement should be triggered now */
    if (sensor_settings->trigger_measurement)
    {
        /* Set sensor configuration */

        bme680_g.tph_sett.os_hum  = sensor_settings->humidity_oversampling;
        bme680_g.tph_sett.os_pres = sensor_settings->pressure_oversampling;
        bme680_g.tph_sett.os_temp = sensor_settings->temperature_oversampling;
        bme680_g.gas_sett.run_gas = sensor_settings->run_gas;
        bme680_g.gas_sett.heatr_temp = sensor_settings->heater_temperature; /* degree Celsius */
        bme680_g.gas_sett.heatr_dur  = sensor_settings->heating_duration; /* milliseconds */
        
        /* Select the power mode */
        /* Must be set before writing the sensor configuration */
        bme680_g.power_mode = BME680_FORCED_MODE;
        /* Set the required sensor settings needed */
        set_required_settings = BME680_OST_SEL | BME680_OSP_SEL | BME680_OSH_SEL | BME680_GAS_SENSOR_SEL;
        
        /* Set the desired sensor configuration */
        bme680_status = bme680_set_sensor_settings(set_required_settings, &bme680_g);
             
        /* Set power mode as forced mode and trigger forced mode measurement */
        bme680_status = bme680_set_sensor_mode(&bme680_g);
        
        /* Get the total measurement duration so as to sleep or wait till the measurement is complete */
        bme680_get_profile_dur(&meas_period, &bme680_g);
        
        /* Delay till the measurement is ready. Timestamp resolution in ms */
        sleep((uint32_t)meas_period);
    }
    
    /* Call the API to get current operation mode of the sensor */
    bme680_status = bme680_get_sensor_mode(&bme680_g);  
    /* When the measurement is completed and data is ready for reading, the sensor must be in BME680_SLEEP_MODE.
     * Read operation mode to check whether measurement is completely done and wait until the sensor is no more
     * in BME680_FORCED_MODE. */
    while (bme680_g.power_mode == BME680_FORCED_MODE)
    {
        /* sleep for 5 ms */
        sleep(5);
        bme680_status = bme680_get_sensor_mode(&bme680_g);
    }
}

/*!
 * @brief       Read the data from registers and populate the inputs structure to be passed to do_steps function
 *
 * @param[in]   time_stamp_trigger      settings of the sensor returned from sensor control function
 * @param[in]   inputs                  input structure containing the information on sensors to be passed to do_steps
 * @param[in]   num_bsec_inputs         number of inputs to be passed to do_steps
 * @param[in]   bsec_process_data       process data variable returned from sensor_control
 *
 * @return      none
 */
static void bme680_bsec_read_data(int64_t time_stamp_trigger, bsec_input_t *inputs, uint8_t *num_bsec_inputs,
    int32_t bsec_process_data)
{
    static struct bme680_field_data data;
    int8_t bme680_status = BME680_OK;
    
    /* We only have to read data if the previous call the bsec_sensor_control() actually asked for it */
    if (bsec_process_data)
    {
        bme680_status = bme680_get_sensor_data(&data, &bme680_g);

        if (data.status & BME680_NEW_DATA_MSK)
        {
            /* Pressure to be processed by BSEC */
            if (bsec_process_data & BSEC_PROCESS_PRESSURE)
            {
                /* Place presssure sample into input struct */
                inputs[*num_bsec_inputs].sensor_id = BSEC_INPUT_PRESSURE;
                inputs[*num_bsec_inputs].signal = data.pressure;
                inputs[*num_bsec_inputs].time_stamp = time_stamp_trigger;
                (*num_bsec_inputs)++;
            }
            /* Temperature to be processed by BSEC */
            if (bsec_process_data & BSEC_PROCESS_TEMPERATURE)
            {
                /* Place temperature sample into input struct */
                inputs[*num_bsec_inputs].sensor_id = BSEC_INPUT_TEMPERATURE;
                #ifdef BME680_FLOAT_POINT_COMPENSATION
                    inputs[*num_bsec_inputs].signal = data.temperature;
                #else
                    inputs[*num_bsec_inputs].signal = data.temperature / 100.0f;
                #endif
                inputs[*num_bsec_inputs].time_stamp = time_stamp_trigger;
                (*num_bsec_inputs)++;
                
                /* Also add optional heatsource input which will be subtracted from the temperature reading to 
                 * compensate for device-specific self-heating (supported in BSEC IAQ solution)*/
                inputs[*num_bsec_inputs].sensor_id = BSEC_INPUT_HEATSOURCE;
                inputs[*num_bsec_inputs].signal = bme680_temperature_offset_g;
                inputs[*num_bsec_inputs].time_stamp = time_stamp_trigger;
                (*num_bsec_inputs)++;
            }
            /* Humidity to be processed by BSEC */
            if (bsec_process_data & BSEC_PROCESS_HUMIDITY)
            {
                /* Place humidity sample into input struct */
                inputs[*num_bsec_inputs].sensor_id = BSEC_INPUT_HUMIDITY;
                #ifdef BME680_FLOAT_POINT_COMPENSATION
                    inputs[*num_bsec_inputs].signal = data.humidity;
                #else
                    inputs[*num_bsec_inputs].signal = data.humidity / 1000.0f;
                #endif  
                inputs[*num_bsec_inputs].time_stamp = time_stamp_trigger;
                (*num_bsec_inputs)++;
            }
            /* Gas to be processed by BSEC */
            if (bsec_process_data & BSEC_PROCESS_GAS)
            {
                /* Check whether gas_valid flag is set */
                if(data.status & BME680_GASM_VALID_MSK)
                {
                    /* Place sample into input struct */
                    inputs[*num_bsec_inputs].sensor_id = BSEC_INPUT_GASRESISTOR;
                    inputs[*num_bsec_inputs].signal = data.gas_resistance;
                    inputs[*num_bsec_inputs].time_stamp = time_stamp_trigger;
                    (*num_bsec_inputs)++;
                }
            }
        }
    }
}

/*!
 * @brief       This function is written to process the sensor data for the requested virtual sensors
 *
 * @param[in]   bsec_inputs         input structure containing the information on sensors to be passed to do_steps
 * @param[in]   num_bsec_inputs     number of inputs to be passed to do_steps
 * @param[in]   output_ready        pointer to the function processing obtained BSEC outputs
 *
 * @return      none
 */
static void bme680_bsec_process_data(bsec_input_t *bsec_inputs, uint8_t num_bsec_inputs, output_ready_fct output_ready)
{
    /* Output buffer set to the maximum virtual sensor outputs supported */
    bsec_output_t bsec_outputs[BSEC_NUMBER_OUTPUTS];
    uint8_t num_bsec_outputs = 0;
    uint8_t index = 0;

    bsec_library_return_t bsec_status = BSEC_OK;
    
    int64_t timestamp = 0;
    float iaq = 0.0f;
    uint8_t iaq_accuracy = 0;
    float temp = 0.0f;
    float raw_temp = 0.0f;
    float raw_pressure = 0.0f;
    float humidity = 0.0f;
    float raw_humidity = 0.0f;
    float raw_gas = 0.0f;
    float static_iaq = 0.0f;
    uint8_t static_iaq_accuracy = 0;
    float co2_equivalent = 0.0f;
    uint8_t co2_accuracy = 0;
    float breath_voc_equivalent = 0.0f;
    uint8_t breath_voc_accuracy = 0;
    float comp_gas_value = 0.0f;
    uint8_t comp_gas_accuracy = 0;
    float gas_percentage = 0.0f;
    uint8_t gas_percentage_acccuracy = 0;
    
    /* Check if something should be processed by BSEC */
    if (num_bsec_inputs > 0)
    {
        /* Set number of outputs to the size of the allocated buffer */
        /* BSEC_NUMBER_OUTPUTS to be defined */
        num_bsec_outputs = BSEC_NUMBER_OUTPUTS;
        
        /* Perform processing of the data by BSEC 
           Note:
           * The number of outputs you get depends on what you asked for during bsec_update_subscription(). This is
             handled under bme680_bsec_update_subscription() function in this example file.
           * The number of actual outputs that are returned is written to num_bsec_outputs. */
        bsec_status = bsec_do_steps(bsec_inputs, num_bsec_inputs, bsec_outputs, &num_bsec_outputs);
        
        /* Iterate through the outputs and extract the relevant ones. */
        for (index = 0; index < num_bsec_outputs; index++)
        {
            switch (bsec_outputs[index].sensor_id)
            {
                case BSEC_OUTPUT_IAQ:
                    iaq = bsec_outputs[index].signal;
                    iaq_accuracy = bsec_outputs[index].accuracy;
                    break;
                case BSEC_OUTPUT_STATIC_IAQ:
                    static_iaq = bsec_outputs[index].signal;
                    static_iaq_accuracy = bsec_outputs[index].accuracy;
                    break;
                case BSEC_OUTPUT_CO2_EQUIVALENT:
                    co2_equivalent = bsec_outputs[index].signal;
                    co2_accuracy = bsec_outputs[index].accuracy;
                    break;
                case BSEC_OUTPUT_BREATH_VOC_EQUIVALENT:
                    breath_voc_equivalent = bsec_outputs[index].signal;
                    breath_voc_accuracy = bsec_outputs[index].accuracy;
                    break;
                case BSEC_OUTPUT_SENSOR_HEAT_COMPENSATED_TEMPERATURE:
                    temp = bsec_outputs[index].signal;
                    break;
                case BSEC_OUTPUT_RAW_PRESSURE:
                    raw_pressure = bsec_outputs[index].signal;
                    break;
                case BSEC_OUTPUT_SENSOR_HEAT_COMPENSATED_HUMIDITY:
                    humidity = bsec_outputs[index].signal;
                    break;
                case BSEC_OUTPUT_RAW_GAS:
                    raw_gas = bsec_outputs[index].signal;
                    break;
                case BSEC_OUTPUT_RAW_TEMPERATURE:
                    raw_temp = bsec_outputs[index].signal;
                    break;
                case BSEC_OUTPUT_RAW_HUMIDITY:
                    raw_humidity = bsec_outputs[index].signal;
                    break;
                case BSEC_OUTPUT_COMPENSATED_GAS:
                    comp_gas_value = bsec_outputs[index].signal;
                    comp_gas_accuracy = bsec_outputs[index].accuracy;
                    break;
                case BSEC_OUTPUT_GAS_PERCENTAGE:
                    gas_percentage = bsec_outputs[index].signal;
                    gas_percentage_acccuracy = bsec_outputs[index].accuracy;
                    break;
                default:
                    continue;
            }
            
            /* Assume that all the returned timestamps are the same */
            timestamp = bsec_outputs[index].time_stamp;
        }
        
        /* Pass the extracted outputs to the user provided output_ready() function. */
        output_ready(timestamp, iaq, iaq_accuracy, temp, humidity, raw_pressure, raw_temp, 
            raw_humidity, raw_gas, bsec_status, static_iaq, co2_equivalent, breath_voc_equivalent);
    }
}

/*!
 * @brief       Runs the main (endless) loop that queries sensor settings, applies them, and processes the measured data
 *
 * @param[in]   sleep               pointer to the system specific sleep function
 * @param[in]   get_timestamp_us    pointer to the system specific timestamp derivation function
 * @param[in]   output_ready        pointer to the function processing obtained BSEC outputs
 * @param[in]   state_save          pointer to the system-specific state save function
 * @param[in]   save_intvl          interval at which BSEC state should be saved (in samples)
 *
 * @return      none
 */
void bsec_iot_loop(sleep_fct sleep, get_timestamp_us_fct get_timestamp_us, output_ready_fct output_ready,
                    state_save_fct state_save, uint32_t save_intvl)
{
    /* Timestamp variables */
    int64_t time_stamp = 0;
    int64_t time_stamp_interval_ms = 0;
    
    /* Allocate enough memory for up to BSEC_MAX_PHYSICAL_SENSOR physical inputs*/
    bsec_input_t bsec_inputs[BSEC_MAX_PHYSICAL_SENSOR];
    
    /* Number of inputs to BSEC */
    uint8_t num_bsec_inputs = 0;
    
    /* BSEC sensor settings struct */
    bsec_bme_settings_t sensor_settings;
    
    /* Save state variables */
    uint8_t bsec_state[BSEC_MAX_STATE_BLOB_SIZE];
    uint8_t work_buffer[BSEC_MAX_WORKBUFFER_SIZE];
    uint32_t bsec_state_len = 0;
    uint32_t n_samples = 0;
    
    bsec_library_return_t bsec_status = BSEC_OK;

    while (1)
    {
        /* get the timestamp in nanoseconds before calling bsec_sensor_control() */
        time_stamp = get_timestamp_us() * 1000;
        
        /* Retrieve sensor settings to be used in this time instant by calling bsec_sensor_control */
        bsec_sensor_control(time_stamp, &sensor_settings);
        
        /* Trigger a measurement if necessary */
        bme680_bsec_trigger_measurement(&sensor_settings, sleep);
        
        /* Read data from last measurement */
        num_bsec_inputs = 0;
        bme680_bsec_read_data(time_stamp, bsec_inputs, &num_bsec_inputs, sensor_settings.process_data);
        
        /* Time to invoke BSEC to perform the actual processing */
        bme680_bsec_process_data(bsec_inputs, num_bsec_inputs, output_ready);
        
        /* Increment sample counter */
        n_samples++;
        
        /* Retrieve and store state if the passed save_intvl */
        if (n_samples >= save_intvl)
        {
            bsec_status = bsec_get_state(0, bsec_state, sizeof(bsec_state), work_buffer, sizeof(work_buffer), &bsec_state_len);
            if (bsec_status == BSEC_OK)
            {
                state_save(bsec_state, bsec_state_len);
            }
            n_samples = 0;
        }
        
        
        /* Compute how long we can sleep until we need to call bsec_sensor_control() next */
        /* Time_stamp is converted from microseconds to nanoseconds first and then the difference to milliseconds */
        time_stamp_interval_ms = (sensor_settings.next_call - get_timestamp_us() * 1000) / 1000000;
        if (time_stamp_interval_ms > 0)
        {
            sleep((uint32_t)time_stamp_interval_ms);
        }
    }
}

/*! @}*/
"""
if __name__ == "__main__":
    logging.critical("This module cannot not run standalone.")
    exit(1)
