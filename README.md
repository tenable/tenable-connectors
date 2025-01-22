# Tenable Connectors Mono-Repo

This is the Tenable Integration Framework's officially supported connectors repository. All connectors that are
accepted into this main branch will be built and deployed for use with the Tenable Integration Framework (hereby simply
referred as the "framework" within this document). While each connector is effectively a individual python project
they are all collectively stored here in order to provide a consistent and unified testing and deployment process that
can be controlled and maintained in a single place.

## Repository Layout

The `base` folder contains the required docker-related files for universally building any of the connecters. The
`Dockerfile` that is stored within this folder should generally be quite close to the one that is vendored within the
`tenint` python library that any developer can use to build & test connectors locally. These files should rarely be
updated (mostly to update the pinnings for any dependent libraries).

The `connectors` folder contains a list of sub-folders (one for each connector) and the folder names should closely
match the name of the connector itself.

## Connector Layout

Connectors are built using the template defined within the `tenint` python library and at a minimum must contain the
following files:

- **pyproject.toml**: This file contains all the relevent information on how to setup the connector with `uv`, as well
  as the required metadata in order to construct the marketplace object for the connector. For details on the required
  fields, refer to the documentation in the `tenint` library.

- **connector.py**: The connector runtime script. This file (as defined by the tenint library) describes the connector
  configuration settings, any required credential settings, and the connector's `main` function to execute whatever
  additional code is needed to launch the connector itself.

- **logo.svg**: An Scalable Vector Graphics file with the associated logo icon to be displayed with the connector in
  the connector marketplace.

- **README.md**: A readme file with any details, instructions, or other information related to the connector itself.

- **tests**: The folder containing the unit tests for the connector. These tests are run using the `pytest` testing suite.

Most of the connectors will contain additional files and folders depending on whats required to drive the connector.
This is prerfectly alright, but all of the above must exist. Some additional requirements that all connectors must at a
minimum meet are the following:

- **Greater than 80% test coverage**
- **Clean code linting from ruff**
- **Clean CodeQL report**
- **No issues greater than medium in Bandit**
- **No discovered issues from pip-audit**
- **No discovered issued from Snyk**

## How to develop a connector

**NOTE** Will be written when we're ready to start accepting outside written integrations

## Running the testing TIF instance

There is an included vagrant file to help enable quick testing of connector images. This VM image exposes Cockpit on
port `9090` and can be interfaced by pointing a web browser to `https://localhost:9090`. A random root password is
also generated and presented as the last line in the setup process for the VM. Look for a line in the provisioning
output that looks like:

```
default: root password is set to 'ZDU3OTU5OWZjZTE0YTkxZTU3ZjJhMjEw'
```

### Initial Install and Setup on MacOS

1. Install `brew`
2. Install QEMU `brew install qemu libvirt`
3. Install Vagrant `brew install --cask vagrant`
4. Install the Vagrant QEMU plugin `vagrant plugin install vagrant-qemu`

### Deploying a new VM

```
vagrant up --provider=qemu
```

### Stopping the VM

```
vagrant halt
```

### Destroying the VM

```
vagrant destroy
```
