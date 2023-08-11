import setuptools

readme_file = ""
license_file = ""

long_description = ""
license = ""

if readme_file:
    with open(readme_file, "r", encoding="utf-8") as fh:
        long_description = fh.read()

if license_file:
    with open(license_file, "r", encoding="utf-8") as fh:
        license = fh.read()

setuptools.setup(
    name="ahe_bindings",
    version="1.0.4",
    author="Benjamin Benčina, Tilen Marc",
    description="Python bindings for the AHE cryptographic library.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.xlab.si/arcadian-iot/ahe-bindings",
    project_urls={
        "Bug Tracker": "https://gitlab.xlab.si/arcadian-iot/ahe-bindings/-/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Development Status :: 1 - Planning",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.6",
    install_requires=[
        'pyserial',
    ],
)
