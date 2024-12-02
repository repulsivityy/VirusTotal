terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region     = "ap-southeast-1"
  access_key = var.access_key
  secret_key = var.secret_key
}

##############################################
## Creates the underlying infrastructure
##############################################

# Creates demo_secrets_scanning VPC
resource "aws_vpc" "demo_secret_scanning_vpc" {
  cidr_block = var.demo_secret_scanning_vpc

  tags = {
    Name        = "demo_secrets_scanning VPC"
    Environment = "demo_secrets_scanning"
  }
}

# Creates Public Facing Subnet
resource "aws_subnet" "demo_secret_scanning_subnet" {
  vpc_id     = aws_vpc.demo_secret_scanning_vpc.id
  cidr_block = var.demo_secret_scanning_subnet

  tags = {
    Name        = "demo_secrets_scanning Subnet"
    Environment = "demo_secrets_scanning"
  }
}

# Creates Internet Gateway
resource "aws_internet_gateway" "demo_secret_scanning_igw" {
  vpc_id = aws_vpc.demo_secret_scanning_vpc.id

  tags = {
    Name        = "demo_secrets_scanning VPC IGW"
    Environment = "demo_secrets_scanning"
  }
}

##############################################
## Creates the underlying routing
##############################################

# Creates Routing Table
resource "aws_route_table" "demo_secret_scanning_rt" {
  vpc_id = aws_vpc.demo_secret_scanning_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.demo_secret_scanning_igw.id
  }

  tags = {
    Name        = "demo_secrets_scanning VPC RT"
    Environment = "demo_secrets_scanning"
  }
}

# Creates Route Table Association
resource "aws_main_route_table_association" "demo_secret_scanning_rt_assocation" {
  vpc_id = aws_vpc.demo_secret_scanning_vpc.id
  route_table_id = aws_route_table.demo_secret_scanning_rt.id
}

#associate Route Table with subnet
resource "aws_route_table_association" "demo_rt_subnet" {
  subnet_id = aws_subnet.demo_secret_scanning_subnet.id
  route_table_id = aws_route_table.demo_secret_scanning_rt.id
}

##############################################
## Creates the security group for demo_secrets_scanning
##############################################

#create Security Group
resource "aws_security_group" "demo_secret_scanning_sg" {
  name   = "demo_secrets_scanning SG"
  vpc_id = aws_vpc.demo_secret_scanning_vpc.id

  #allow ingress
  ingress {
    description = "RDP to Win Server"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
  }
  ingress {
    description = "HTTPS access"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  }
  ingress {
    description = "Agent Comms"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 41002
    to_port     = 41002
    protocol    = "tcp"
  }

  #allow egress  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "demo_secrets_scanning SG"
  }
}


##############################################
## Creates EC2 for demo_secrets_scanning
##############################################

# Creates an EIP
resource "aws_eip" "demo_secret_scanning_eip" {
  instance = aws_instance.demo_secret_scanning_server.id

  tags = {
    Name = "demo_secrets_scanning EIP"
  }
}

resource "aws_key_pair" "public_key" {
  key_name   = var.key_name
  public_key = var.public_key
}

# Creates Win Server EC2 instance
resource "aws_instance" "demo_secret_scanning_server" {
  ami             = var.demo_secret_scanning_ami
  instance_type   = var.demo_secret_scanning_instance
  subnet_id       = aws_subnet.demo_secret_scanning_subnet.id
  security_groups = [aws_security_group.demo_secret_scanning_sg.id]
  key_name        = aws_key_pair.public_key.id

  root_block_device {
    volume_size = var.root_volume_size
  }

  tags = {
    Name        = "demo_secrets_scanning"
    Environment = "demo_secrets_scanning"
  }
}