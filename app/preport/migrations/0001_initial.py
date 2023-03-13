# Generated by Django 3.2.5 on 2021-08-12 15:15

from django.db import migrations, models
import django.db.models.deletion
import martor.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='DB_CWE',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cwe_id', models.IntegerField()),
                ('cwe_name', models.CharField(blank=True, max_length=255)),
                ('cwe_description', models.CharField(blank=True, max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='DB_Product',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255)),
                ('description', martor.models.MartorField()),
            ],
        ),
        migrations.CreateModel(
            name='DB_Report',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('report_id', models.CharField(max_length=255)),
                ('title', models.CharField(max_length=255)),
                ('executive_summary_image', models.TextField(blank=True, null=True)),
                ('categories_summary_image', models.TextField(blank=True, null=True)),
                ('executive_summary', martor.models.MartorField()),
                ('scope', martor.models.MartorField()),
                ('outofscope', martor.models.MartorField()),
                ('methodology', martor.models.MartorField()),
                ('recommendation', martor.models.MartorField()),
                ('creation_date', models.DateTimeField(auto_now_add=True)),
                ('report_date', models.DateTimeField()),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='preport.db_product')),
            ],
        ),
        migrations.CreateModel(
            name='DB_Finding_Template',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('finding_id', models.CharField(blank=True, max_length=200)),
                ('title', models.CharField(blank=True, max_length=200)),
                ('severity', models.CharField(blank=True, max_length=200)),
                ('cvss_base_score', models.CharField(blank=True, max_length=200)),
                ('cvss_score', models.DecimalField(decimal_places=1, default=0, max_digits=3)),
                ('description', martor.models.MartorField()),
                ('location', martor.models.MartorField()),
                ('impact', martor.models.MartorField()),
                ('recommendation', martor.models.MartorField()),
                ('references', martor.models.MartorField()),
                ('cwe', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='preport.db_cwe')),
            ],
        ),
        migrations.CreateModel(
            name='DB_Finding',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('finding_id', models.CharField(blank=True, max_length=200)),
                ('status', models.CharField(blank=True, default='Open', max_length=200)),
                ('title', models.CharField(blank=True, max_length=200)),
                ('severity', models.CharField(blank=True, max_length=200)),
                ('cvss_base_score', models.CharField(blank=True, max_length=200)),
                ('cvss_score', models.DecimalField(decimal_places=1, default=0, max_digits=3)),
                ('description', martor.models.MartorField()),
                ('location', martor.models.MartorField()),
                ('impact', martor.models.MartorField()),
                ('recommendation', martor.models.MartorField()),
                ('references', martor.models.MartorField()),
                ('cwe', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='preport.db_cwe')),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='preport.db_report')),
            ],
        ),
        migrations.CreateModel(
            name='DB_Appendix',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(blank=True, max_length=200)),
                ('description', martor.models.MartorField()),
                ('finding', models.ManyToManyField(blank=True, related_name='appendix_finding', to='preport.DB_Finding')),
            ],
        ),
        migrations.CreateModel(
        name='DB_Risk_Management',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('risk_id', models.CharField(blank=True, max_length=200)),
                ('risk_number', models.CharField(blank=True, max_length=200)),
                ('risk_owner', models.CharField(blank=True, max_length=200)),
                ('process_service_name', models.CharField(blank=True, max_length=200)),
                ('asset_category', models.CharField(blank=True, max_length=200)),
                ('asset_name', models.CharField(blank=True, max_length=200)),
                ('threat', martor.models.MartorField()),
                ('vulnerability', martor.models.MartorField()),
                ('impact_component', martor.models.MartorField()),
                ('current_control', martor.models.MartorField()),
                ('inherent_risk_probability', models.CharField(blank=True, max_length=200)),
                ('inherent_risk_severity', models.CharField(blank=True, max_length=200)),
                ('inherent_risk_value', models.CharField(blank=True, max_length=200)),
                ('type_of_risk', models.CharField(blank=True, max_length=200)),
                ('risk_handling', models.CharField(blank=True, max_length=200)),
                ('risk_treatment_plan', martor.models.MartorField()),
                ('residual_risk_probability', models.CharField(blank=True, max_length=200)),
                ('residual_risk_severity', models.CharField(blank=True, max_length=200)),
                ('residual_risk_value', models.CharField(blank=True, max_length=200)),
                ('reference', martor.models.MartorField()),
                ('target_date', models.CharField(blank=True, max_length=200)),
                ('status', models.CharField(blank=True, max_length=200)),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='preport.db_report')),
                
            ],
        ),

        migrations.CreateModel(
        name='DB_Risk_Management_Template',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('risk_id', models.CharField(blank=True, max_length=200)),
                ('risk_number', models.CharField(blank=True, max_length=200)),
                ('risk_owner', models.CharField(blank=True, max_length=200)),
                ('process_service_name', models.CharField(blank=True, max_length=200)),
                ('asset_category', models.CharField(blank=True, max_length=200)),
                ('asset_name', models.CharField(blank=True, max_length=200)),
                ('threat', martor.models.MartorField()),
                ('vulnerability', martor.models.MartorField()),
                ('impact_component', martor.models.MartorField()),
                ('current_control', martor.models.MartorField()),
                ('inherent_risk_probability', models.CharField(blank=True, max_length=200)),
                ('inherent_risk_severity', models.CharField(blank=True, max_length=200)),
                ('inherent_risk_value', models.CharField(blank=True, max_length=200)),
                ('type_of_risk', models.CharField(blank=True, max_length=200)),
                ('risk_handling', models.CharField(blank=True, max_length=200)),
                ('risk_treatment_plan', martor.models.MartorField()),
                ('residual_risk_probability', models.CharField(blank=True, max_length=200)),
                ('residual_risk_severity', models.CharField(blank=True, max_length=200)),
                ('residual_risk_value', models.CharField(blank=True, max_length=200)),
                ('reference', martor.models.MartorField()),
                ('target_date', models.CharField(blank=True, max_length=200)),
                ('status', models.CharField(blank=True, max_length=200)),
            ],
        ),
    ]
