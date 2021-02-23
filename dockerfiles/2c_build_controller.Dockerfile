# 2021 Collegiate eCTF
# SCEWL Bus Controller build Dockerfile
# Ben Janis
#
# (c) 2021 The MITRE Corporation

ARG DEPLOYMENT

###################################################################
# Since we want to copy files from the sss container,             #
# first create an intermediate stage:                             #
#                                                                 #
FROM ${DEPLOYMENT}/sss:latest as sss                                     
#                                                                 #
# Then see box below                                              #
###################################################################

# load the base controller image
FROM ${DEPLOYMENT}/controller:base

# map in controller to /sed
# NOTE: only controller/ and its subdirectories in the repo are accessible to this Dockerfile as .
ADD . /sed

###################################################################
# Copy secrets from the SSS container                             #
#                                                                 #
ARG SCEWL_ID
COPY --from=sss /secrets/${SCEWL_ID}.secret /sed/sed.secret.h
#                                                                 #
###################################################################

###################################################################
# Build controller                                                #
WORKDIR /sed
ARG SCEWL_ID
RUN make SCEWL_ID=${SCEWL_ID}
# Move controller binary to root directory                        #
RUN mv /sed/gcc/controller.bin /controller
# Move debugging elf to root directory (TODO remove)
RUN cp /sed/gcc/controller.axf /controller.elf
RUN cp /sed/sed.secret.h /secret.h
###################################################################

###################################################################
# IT IS NOT RECOMMENDED TO KEEP DEPLOYMENT-WIDE SECRETS IN THE    #
# SED FILE STRUCTURE PAST BUILDING, SO CLEAN UP HERE AS NECESSARY #
#                                                                 #
# Remove the secrets file                                         #
RUN rm /sed/sed.secret.h
# Remove build folder, it isn't needed now                        #
RUN rm -r /sed/gcc
###################################################################
