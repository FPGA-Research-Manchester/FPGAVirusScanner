from setuptools import setup, find_packages

setup(
    name='FPGA_virus_scanner',
    version='1.0.0',
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.7',
    description='Virus scanner for FPGA designs with some additional scripts used in the scanning.',
    entry_points={
        'console_scripts': [
            'virusscanner=virusscanner.app:main',
            'getgraph=virusscanner.getgraph.app:main',
            'agcombiner=virusscanner.getgraph.agcombiner.app:main',
            'bitstreamtograph=virusscanner.getgraph.bitstreamtograph.app:main',
            'agsiteadder=virusscanner.getgraph.agsiteadder.app:main'
        ],
    }
)
