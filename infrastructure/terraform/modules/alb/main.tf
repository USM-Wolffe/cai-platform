variable "name_prefix" { type = string }
variable "subnet_ids"  { type = list(string) }
variable "vpc_id"      { type = string }
variable "tags"        { type = map(string) }

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb-sg"
  description = "Security group for cai platform ALB"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_lb" "main" {
  name               = "${var.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids
  tags               = var.tags
}

# Target group: platform-api (prod)
resource "aws_lb_target_group" "api" {
  name        = "${var.name_prefix}-api-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check {
    path                = "/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
  tags = var.tags
}

# Target group: platform-ui (prod)
resource "aws_lb_target_group" "ui" {
  name        = "${var.name_prefix}-ui-tg"
  port        = 8501
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check {
    path                = "/ui/api/health"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 10
  }
  tags = var.tags
}

# Target group: platform-api-staging
resource "aws_lb_target_group" "api_staging" {
  name        = "${var.name_prefix}-api-staging-tg"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check {
    path = "/health"
  }
  tags = var.tags
}

# Target group: platform-ui-staging
resource "aws_lb_target_group" "ui_staging" {
  name        = "${var.name_prefix}-ui-staging-tg"
  port        = 8501
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"
  health_check {
    path    = "/ui/api/health"
    timeout = 10
  }
  tags = var.tags
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_listener_rule" "ui" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ui.arn
  }
  condition {
    path_pattern { values = ["/ui", "/ui/*"] }
  }
}

resource "aws_lb_listener_rule" "api_staging" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 20
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api_staging.arn
  }
  condition {
    path_pattern { values = ["/staging", "/staging/*"] }
  }
}

resource "aws_lb_listener_rule" "ui_staging" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 30
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ui_staging.arn
  }
  condition {
    path_pattern { values = ["/staging-ui", "/staging-ui/*"] }
  }
}

output "alb_dns"              { value = aws_lb.main.dns_name }
output "alb_suffix"           { value = replace(aws_lb.main.arn, ".*loadbalancer/", "") }
output "alb_sg_id"            { value = aws_security_group.alb.id }
output "api_target_group_arn" { value = aws_lb_target_group.api.arn }
output "ui_target_group_arn"  { value = aws_lb_target_group.ui.arn }
output "api_staging_tg_arn"   { value = aws_lb_target_group.api_staging.arn }
output "ui_staging_tg_arn"    { value = aws_lb_target_group.ui_staging.arn }
