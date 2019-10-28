==================
FPGA Virus scanner
==================

Program for scanning implemented FPGA designs for malicious intent. Below the program is described and the necessary resources to run the examples are given as well. All of the examples below use the short option flags but alternatives exist as well.

For more details about the options use the *--help* flag.

VirusScanner
============

This executable is the main program which scans the given implemented designs.

How to use
----------

An example on how to scan the design in ring_osci_MUX_short.json file is shown below::

    virusscanner -i ring_osci_MUX_short.json -c config.ini -o output.txt

The above command runs the virus scanner on the implemented graph in the "ring_osci_MUX_short.json" file based on the options set in the "config.ini" file and outputs the results to the "output.txt" file.

Config
------

The config is used to configure the virus scanner and the tools it uses. The config is parsed using the Python's *ConfigParser* package so it consists of sections and options. The config should have the following items specified:

* virus_signatures - Names of the virus signature packages to be executed
    * Specific virus_signature options described in the next section
* connection_attributes - Optional section for adding attributes to connections
    * attributes_file - Path to the CSV file describing which connections get which attributes.
* removables
    * connections_file - Path to the TXT file describing which connections should be removed from the implementation graph before the scans.

virus_signatures
----------------

Here are the different available virus signatures described which can be set up in the config by adding the name of the virus signature class under the *virus_signatures* section. Since the different signatures give out scores, the results can be scaled by adding an equals sign and the desired scale for that specific signature.

#) Ring oscillator detection
    * virusscanner.parsing.signatures.ring_oscillator_detection.CombinatorialLoopDetector
    * Needs a section called *ring_oscillator_detection*
        *  Requires an option called *ignored_attributes_file* to have an input *.txt* file
    * This detects loops in the given implementation.
#) Disallowed port detection
    * virusscanner.parsing.signatures.node_detection.PortDetector
    * Needs a section called *node_detection*
        * Requires an option called *disallowed_nodes_file* to have an input *.csv* file
    * Can detect disallowed port usages like snooping on neighbouring designs.
#) Disallowed path detection
    * virusscanner.parsing.signatures.path_detection.PathDetector
    * Needs a section called *path_detection*
        * Requires an option called *disallowed_begin_nodes_file* to have an input *.csv* file
        * Requires an option called *disallowed_destination_nodes_file* to have an input *.csv* file
    * Can detect disallowed path usages like paths next to leaky long wires.
#) Short circuit detection
    * virusscanner.parsing.signatures.short_detection.ShortCircuitDetector
    * Needs a section called *short_detection*
        * Requires an option called *short_location_file* to have an input *.csv* file
    * This detects outputs with multiple used inputs which can cause short circuits.
#) Antenna detection
    * virusscanner.parsing.signatures.antenna_detection.AntennaDetector
    * Needs a section called *antenna_detection*
        * Requires an option called *allowed_input_antennas_file* to have an input *.csv* file
        * Requires an option called *allowed_output_antennas_file* to have an input *.csv* file
    * Can detect undesired dangling input and output wires.
#) Disallowed path detection
    * virusscanner.parsing.signatures.unspecified_path_detection.UnspecifiedPathDetector
    * Needs a section called *unspecified_path_detection*
        * Requires an option called *specified_begin_nodes_file* to have an input *.csv* file
        * Requires an option called *specified_end_nodes_file* to have an input *.csv* file
        * Requires an option called *specified_routing_nodes_file* to have an input *.csv* file
    * Can detect paths which start or end at specified ports but use disallowed routing ports. The detected paths will be from the end ports which don't start at the specified start ports.
#) Fan-out detection
    * virusscanner.parsing.signatures.fan_out_detection.FanOutDetector
    * Needs a section called *fan_out_begin_nodes_file*
        * Requires an option called *fan_out_begin_nodes_file* to have an input *.csv* file
        * Requires an option called *fan_out_end_nodes_file* to have an input *.csv* file
    * Can detect all nodes which are connected to too many end nodes. The threshold is set to 100 temporarily.
#) Attribute detection
    * virusscanner.parsing.signatures.attribute_detection.AttributeDetector
    * Can detect all nodes with the attribute "LATCH".

To look up the formats of the option files look at the files under the resources directory.

Development
===========

For development make sure to use the *flake8* and *coverage* libraries and for creating the executables use *PyInstaller*. The project does use Python 3.7 features so to build the scanner Python 3.7 is required.

Under resources directory you can find some malicious design examples picked up by the scanner.

How to build
------------

First install the requirements of the project to your *venv* environment using pip::

    pip install -r requirements.txt

Then you can use the following command to create all of the scripts which act like the executables::

    pip install .

Making executables
------------------

In order to make executables use the *PyInstaller* tool got from pip. When making the *VirusScanner* tool
make sure to add the virus scanner packages given in the config as hidden imports like in the following command::

    pyinstaller virusscanner/__main__.py -n virusscanner -F --hidden-import=virusscanner.parsing.signatures.ring_oscillator_detection

