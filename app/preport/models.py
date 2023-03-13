# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models
from django.utils import timezone
from martor.models import MartorField


# ---------- CWE ------------

class DB_CWE(models.Model):
	cwe_id = models.IntegerField(blank=False, unique=True)
	cwe_name = models.CharField(max_length=255, blank=True)
	cwe_description = models.TextField(blank=True)
	
# ---------- Product ------------

class DB_Product(models.Model):
	name = models.CharField(max_length=255, blank=False)
	description = MartorField()

# ---------- Report ------------

class DB_Report(models.Model):
	product = models.ForeignKey(DB_Product, on_delete=models.CASCADE)
	report_id = models.CharField(max_length=255, blank=False, unique=True)
	title = models.CharField(max_length=255, blank=False)
	executive_summary_image = models.TextField(blank=True, null=True)
	categories_summary_image = models.TextField(blank=True, null=True)
	executive_summary = MartorField()
	scope = MartorField()
	outofscope = MartorField()
	methodology = MartorField()
	recommendation = MartorField()
	creation_date = models.DateTimeField(auto_now_add=True)
	report_date = models.DateTimeField(blank=False)


# ---------- Finding ------------

class DB_Finding(models.Model):
	report = models.ForeignKey(DB_Report, on_delete=models.CASCADE)
	finding_id = models.CharField(blank=True, max_length=200)
	status = models.CharField(blank=True, max_length=200, default="Open")
	title = models.CharField(blank=True, max_length=200)
	severity = models.CharField(blank=True, max_length=200)
	cvss_base_score = models.CharField(blank=True, max_length=200)
	cvss_score = models.DecimalField(max_digits=3, decimal_places=1, default=0)
	description = MartorField(blank=True)
	location = MartorField(blank=True)
	impact = MartorField(blank=True)
	recommendation = MartorField(blank=True)
	references = MartorField(blank=True)
	cwe = models.ForeignKey(DB_CWE, on_delete=models.CASCADE)

# ---------- Finding templates ------------

class DB_Finding_Template(models.Model):
	finding_id = models.CharField(blank=False, max_length=200)
	title = models.CharField(blank=False, max_length=200)
	severity = models.CharField(blank=True, max_length=200)
	cvss_base_score = models.CharField(blank=True, max_length=200)
	cvss_score = models.DecimalField(max_digits=3, decimal_places=1, default=0)
	description = MartorField(blank=True)
	location = MartorField(blank=True)
	impact = MartorField(blank=True)
	recommendation = MartorField(blank=True)
	references = MartorField(blank=True)
	cwe = models.ForeignKey(DB_CWE, on_delete=models.CASCADE)

# ---------- Appendix ------------

class DB_Appendix(models.Model):
	finding = models.ManyToManyField(DB_Finding, related_name='appendix_finding', blank=True)
	title = models.CharField(blank=False, max_length=200)
	description = MartorField()


# ---------- Attack Tree ------------

class DB_AttackTree(models.Model):
	finding = models.ManyToManyField(DB_Finding, related_name='attacktree_finding', blank=True)
	title = models.CharField(blank=False, max_length=200)
	attacktree = models.TextField(blank=True, null=True)
	svg_file = models.TextField(blank=True, null=True)

# ---------- Custom Field ------------

class DB_Custom_field(models.Model):
	#finding = models.ManyToManyField(DB_Finding, related_name='custom_field_finding', blank=True)
	finding = models.ForeignKey(DB_Finding, related_name='custom_field_finding', blank=True, on_delete=models.CASCADE)
	title = models.CharField(blank=False, max_length=200)
	description = MartorField(blank=True, null=True)

# ---------- Attack Flow ------------

class DB_AttackFlow(models.Model):
	finding = models.ManyToManyField(DB_Finding, related_name='attackflow_finding', blank=True)
	title = models.CharField(blank=False, max_length=200)
	attackflow_afb = models.TextField(blank=True, null=True)
	attackflow_png = models.TextField(blank=True, null=True)

# ---------- Risk Management ------------

class DB_Risk_Management(models.Model):
	report = models.ForeignKey(DB_Report, on_delete=models.CASCADE)
	risk_id = models.CharField(blank=True, max_length=200)
	risk_number = models.CharField(blank=True, max_length=200)
	risk_owner = models.CharField(blank=True, max_length=200)
	process_service_name = models.CharField(blank=True, max_length=200)
	asset_category = models.CharField(blank=True, max_length=200)
	asset_name = models.CharField(blank=True, max_length=200)
	threat = MartorField(blank=True)
	vulnerability = MartorField(blank=True)
	impact_component = MartorField(blank=True)
	current_control = MartorField(blank=True)
	inherent_risk_probability = models.CharField(blank=True, max_length=200)
	inherent_risk_severity = models.CharField(blank=True, max_length=200)
	inherent_risk_value = models.CharField(blank=True, max_length=200)
	type_of_risk = models.CharField(blank=True, max_length=200)
	risk_handling = models.CharField(blank=True, max_length=200)
	risk_treatment_plan = MartorField(blank=True)
	residual_risk_probability = models.CharField(blank=True, max_length=200)
	residual_risk_severity = models.CharField(blank=True, max_length=200)
	residual_risk_value = models.CharField(blank=True, max_length=200)
	reference = MartorField(blank=True)
	target_date = models.CharField(blank=True, max_length=200)
	status = models.CharField(blank=True, max_length=200)

	# ---------- Risk Management Template------------

class DB_Risk_Management_Template(models.Model):
	risk_id = models.CharField(blank=True, max_length=200)
	risk_number = models.CharField(blank=True, max_length=200)
	risk_owner = models.CharField(blank=True, max_length=200)
	process_service_name = models.CharField(blank=True, max_length=200)
	asset_category = models.CharField(blank=True, max_length=200)
	asset_name = models.CharField(blank=True, max_length=200)
	threat = MartorField(blank=True)
	vulnerability = MartorField(blank=True)
	impact_component = MartorField(blank=True)
	current_control = MartorField(blank=True)
	inherent_risk_probability = models.CharField(blank=True, max_length=200)
	inherent_risk_severity = models.CharField(blank=True, max_length=200)
	inherent_risk_value = models.CharField(blank=True, max_length=200)
	type_of_risk = models.CharField(blank=True, max_length=200)
	risk_handling = models.CharField(blank=True, max_length=200)
	risk_treatment_plan = MartorField(blank=True)
	residual_risk_probability = models.CharField(blank=True, max_length=200)
	residual_risk_severity = models.CharField(blank=True, max_length=200)
	residual_risk_value = models.CharField(blank=True, max_length=200)
	reference = MartorField(blank=True)
	target_date = models.CharField(blank=True, max_length=200)
	status = models.CharField(blank=True, max_length=200)
	
