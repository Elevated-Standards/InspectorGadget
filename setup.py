from setuptools import setup, find_packages

setup(
    name="autopilot",
    version="0.1.0",
    packages=find_packages(where="findings"),
    package_dir={"": "findings"},
    install_requires=[
        "boto3>=1.26.0",
    ],
    python_requires=">=3.7",
)