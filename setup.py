import setuptools

with open("README.md") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pdfguard",  # Replace with your own username
    version="1",
    author="pdfguard",
    author_email="pdfguard",
    description="pdfguard",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pdfguard/pdfguard",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[],
)
