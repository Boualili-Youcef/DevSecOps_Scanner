# EXEMPLE RÉSERVÉ AUX SCANS. Ne jamais exécuter terraform apply.
terraform {
  required_version = ">= 1.5, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.0.0"
    }
  }
}

resource "aws_security_group" "demo" {
  name        = "guardian-demo-never-deploy"
  description = "Groupe de sécurité réservé aux scans de démonstration"
  vpc_id      = "vpc-00000000000000000"

  ingress {
    description = "Accès SSH de démonstration"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"] # Volontairement vulnérable.
  }

  egress {
    description = "HTTPS vers un exemple de réseau privé"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/24"]
  }
}

# Rattachement statique pour éviter un groupe inutilisé. Ne jamais déployer.
resource "aws_network_interface" "demo" {
  subnet_id       = "subnet-00000000000000000"
  security_groups = [aws_security_group.demo.id]
}

# Démonstration de sécurité.
