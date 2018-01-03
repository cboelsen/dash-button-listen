from distutils.core import setup
from distutils.extension import Extension

from Cython.Build import cythonize


extensions = [
    Extension(
        "dhcp_sniffer",
        ["src/dhcp_sniffer.pyx"],
        libraries=["pcap"],
        language="c++",
    ),
]


setup(
    name="dash-button-listen",
    version="0.0.1",
    description="A much more lightweight Amazon dash button sniffer.",
    author="Christian Boelsen",
    packages=['dash_button_listen'],
    license="LGPLv3",
    long_description=open('README.md', 'r').read(),
    entry_points={
        'console_scripts': [
            'dash-button-listen = dash_button_listen:main'
        ],
    },
    install_requires=[
        'cython>=0.27.3',
    ],
    ext_modules=cythonize(extensions),
)
