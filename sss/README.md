# 0xDACC SCEWL Security Server (SSS)
The SCEWL Security Server supports registration and deregistration functionality
for SCEWL Enabled Devices. It also includes scripts to support the creation
of SCEWL deployments. The SSS is one of two components our team had to implement
(the other being the SCEWL Bus Controller in `/controller/`).

## Files
The SCEWL Security Server uses several files:

* `sss.py`: Implements the main functionality of the SCEWL Security Server. It runs
  in a loop, registering and deregistering SEDs.
* `helper.py`: Helps with deployment, performing tasks for `create_deployment`, `add_sed`,
  and `remove_sed`.
* `vault.py`: Handles storage of data for each SED. TODO: remove from readme if unused.
* `/secrets`: On the SSS docker, the `/secrets` directory is used for data storage, including
  sensitive information.
* `/secrets/depl_id_{id}`: The secrets file assigned to a deployment id. This is created at
  `create_deployment` and will be assigned to an SED at `add_sed`.
* `/secrets/{SCEWL_ID}.secret`: The secrets file assigned to an SED. Each is equivalent to
  one of the deployment secrets files.
* `/secrets/mapping`: Maps between SCEWL IDs and deployment IDs. Updated at `add_sed` and `remove_sed`.
* `/secrets/auth`: Stores the authorization tokens for registration/deregistration of each SED.
  Updated at `add_sed` and `remove_sed`.
* `/secrets/{SCEWL_ID}.vault`: Stores data on disk for the SED. TODO: remove from readme if unused.

## Data Fields
The SSS interacts with the SCEWL Bus Controllers during registration and deregistration.
The following fields are exchanged in these messages (see `/controller/controller.h` for structs:

* `seq`:
  * set to 1
* `KNOWN_SEQS[256]`:
  * set to 
