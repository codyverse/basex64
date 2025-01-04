from setuptools import setup, find_packages

setup(
    name="basex64",
    version="0.0.1.250102",
    description="A simple cryptographic tool for storing data in distributed version control systems like Git.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Andrii Burkatskyi aka andr11b",
    author_email="4ndr116@gmail.com",
    url="https://github.com/codyverse/basex64",
    license="MIT",
    packages=find_packages(include=["basex64"]),
    install_requires=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires=">=3.8",
)
