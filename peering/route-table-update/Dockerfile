FROM python:3.7

# run some updates and set the timezone to eastern
# also install jq json viewer (https://stedolan.github.io/jq/)
# example jq usage: aws ec2 describe-instances | jq
RUN apt-get clean && apt-get update && apt-get -qy upgrade \
    && apt-get -qy install locales tzdata apt-utils software-properties-common build-essential python3 nano graphviz \
    && locale-gen en_US.UTF-8 \
    && ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime \
    && dpkg-reconfigure -f noninteractive tzdata \
    && apt-get -qy install jq

# install custodian dependencies and custodian mailer tool (c7n-mailer)
RUN pip3 install boto3 botocore \
    && pip3 install awscli --upgrade pip \
    && pip3 install awscli-login

# install Terraform
ENV TERRAFORM_VERSION=0.12.19
RUN wget --quiet https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip --directory-prefix /tmp && \
    unzip /tmp/terraform_${TERRAFORM_VERSION}_linux_amd64.zip -d /usr/bin && \
    rm /tmp/terraform_${TERRAFORM_VERSION}_linux_amd64.zip

# clean up after ourselves, keep image as lean as possible
RUN apt-get remove -qy --purge software-properties-common \
    && apt-get autoclean -qy \
    && apt-get autoremove -qy --purge \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

CMD [ "/bin/bash" ]
