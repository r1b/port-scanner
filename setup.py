from setuptools import find_packages, setup

setup(
    name="port-scanner",
    version="0.1",
    description="A simple port scanner",
    url="https://github.com/r1b/port-scanner",
    author="Robert Jensen",
    author_email="robert.cole.jensen@gmail.com",
    license="BSD",
    packages=find_packages(),
    # package_data={"fourmat": ("assets/*.*", "assets/.*")},
    install_requires=(
        "icmplib",
        "typer",
    ),
    entry_points={"console_scripts": ("port-scanner = port_scanner:cli",)},
)
