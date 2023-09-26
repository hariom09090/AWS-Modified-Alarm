import boto3
import os
import json
import humanize
from tabulate import tabulate
import humanize
from datetime import datetime
import logging

# Initialize the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def send_email(subject, body):
    try:
        client = boto3.client('sns')
        client.publish(
            TopicArn=os.environ.get('SNS_Topic_Arn'),
            Message=body,
            Subject=subject
        )
        logger.info(f"Email sent")
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")

def execute_command(instance_id, command, platform):
    try:
        ssm_client = boto3.client('ssm')
        if 'linux' in platform.lower():
            documentName = 'AWS-RunShellScript'
        elif 'windows' in platform.lower():
            documentName = 'AWS-RunPowerShellScript'
        else:
            logger.error("No platform found...please verify")
        logger.info(f"Selected SSM Document -- '{documentName}'")
        logger.info(f"Received command -- '{command}' to be run on '{instance_id}'")
        response = ssm_client.send_command(
            Targets=[
                {
                    'Key': 'InstanceIds',
                    'Values': [instance_id]
                }
            ],
            DocumentName=documentName,
            Parameters={'commands': [command]},
        )

        command_id = response['Command']['CommandId']

        waiter = ssm_client.get_waiter('command_executed')
        waiter.wait(
            CommandId=command_id,
            InstanceId=instance_id,
        )

        response = ssm_client.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )

        if 'Status' in response and response['Status'] == 'Success':
            logger.info(f"Command '{command}' ran successfully on the instance '{instance_id}'")
            return response['StandardOutputContent']
        else:
            error_message = f"Command '{command}' execution failed or no output available."
            if 'Status' in response and response['Status'] == 'Failed':
                error_message += f"\nFailure Reason: {response['StatusDetails']}"
            logger.error(error_message)
            return error_message

    except Exception as e:
        err = f"\nAn error occured in SSM : {str(e)}\n"
        logger.error(e)
        return e

def format_output(output, platform):
    logger.info(f"Formatting output...received platform.. '{platform}'")
    if 'windows' in platform.lower():
        lines = output.strip().split('\n')
        headers = lines[0].split()
        data = [line.split() for line in lines[2:]]

        for row in data:
            row[2:5] = [format_size(size) for size in row[2:5]]

        formatted_output = tabulate(data, headers, tablefmt="pretty")
    
    elif 'linux' in platform.lower():
        lines = output.strip().split('\n')
        headers = [header.strip() for header in lines[0].split()]
        data = [line.strip().split(None, 4) for line in lines[1:]]

        formatted_output = tabulate(data, headers, tablefmt="pretty")
    else:
        logger.error(f"Not received platform details for output:- \t\t\n'{output}'\n")
    return formatted_output
    
def format_size(size):
    try:
        size_in_kb = float(size)
        size_in_bytes = size_in_kb * 1024
        return humanize.naturalsize(size_in_bytes)
    except ValueError:
        return size

def format_output_windisk(output):
    lines = output.strip().split('\n')
    headers = lines[0].split()
    data = [line.split() for line in lines[2:]]
    
    # Convert size values to human-readable format
    for row in data:
        row[1] = format_size_windisk(row[1])  # Format Size
        row[2] = format_size_windisk(row[2])  
    formatted_output = tabulate(data, headers, tablefmt="pretty")
    return formatted_output

def format_size_windisk(size):
    try:
        size_in_bytes = int(size)
        return humanize.naturalsize(size_in_bytes)
    except ValueError:
        return size

def cpumsg(instance_id, platform):
    logger.info(f"Fetching process consuming high CPU on '{instance_id}'")
    try:
        email_message = ''
        
        if 'windows' in platform.lower():
            top_output = execute_command(instance_id, 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5', platform)
            formatted_top_output = format_output(top_output, platform)
            
        elif 'linux' in platform.lower():
            top_output = execute_command(instance_id, 'top -b -n 1 | head -6', platform)
            topfive_output = execute_command(instance_id, 'ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head -6', platform)
            formatted_top_output = format_output(topfive_output, platform)
            email_message = f"Top Command Output:-\t\t\n{top_output}\n"

        else:
            logger.error(f"Platform details not received in CPU function")
            
        email_message += f"Top 5 processes consuming high CPU:- \t\t\n{formatted_top_output}\n"
        logger.info(email_message)

    except Exception as e:
        email_message = f"An error occured in cpumsg: {str(e)}"
        logger.error(email_message)
    return email_message

def memmsg(instance_id, platform):
    logger.info(f"Fetching process consuming high Memory on '{instance_id}'")
    try:
        email_message = ''
        
        if 'linux' in platform.lower():
            free_output = execute_command(instance_id, 'free -h', platform)
            top_output = execute_command(instance_id, 'ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem | head -6', platform)
            formatted_top_output = format_output(top_output, platform)
            email_message = f"Memory Consumption Output:- \t\t\n{format_output(free_output, platform)}\n"
        
        elif 'windows' in platform.lower():
          free_output = execute_command(instance_id, 'Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty FreePhysicalMemory', platform)
          total_output = execute_command(instance_id, 'Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty TotalVisibleMemorySize', platform)
          top_output = execute_command(instance_id, 'Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5', platform)
          formatted_top_output = format_output(top_output, platform)
         # Convert the values from MB to GB
          free_output_gb = format_size(free_output)
          total_output_gb = format_size(total_output)
          email_message = f"Free Memory: {free_output_gb}\nTotal Memory: {total_output_gb}\n\n"
        
        else:
            logger.error(f"Platform details not received in Memory function")
        
        email_message += f"Top 5 processes consuming high memory:- \t\t\n{formatted_top_output}\n"
        logger.info(email_message) 

    except Exception as e:
        email_message = f"An error occured in memmsg: {str(e)}"
        logger.error(email_message)
    return email_message

def diskmsg(instance_id, platform):
    logger.info(f"Fetching process consuming high Memory on '{instance_id}'")
    try:
        email_message = ''

        if 'linux' in platform.lower():
            df_output = execute_command(instance_id, 'df -h', platform)
            formatted_output = format_output(df_output, platform)

        elif 'windows' in platform.lower():
            df_output = execute_command(instance_id, 'Get-WmiObject -Class Win32_LogicalDisk | Select-Object -Property DeviceID, Size, FreeSpace', platform)
            formatted_output = format_output_windisk(df_output)

        else:
            logger.error(f"Platform details not received in Memory function")
        
        email_message = f"Storage Utilization Details:- \t\t\n{formatted_output}\n"
        logger.info(email_message) 

    except Exception as e:
        email_message = f"An error occured in diskmsg: {str(e)}"
        logger.error(email_message)

    return email_message

def instance_metric_details(instance_id, metric_name, platform):
    logger.info(f"Received Alarm for '{metric_name}' of '{instance_id}'")
    email_message = ''
    
    try:
        if metric_name == 'CPUUtilization':
            email_message = cpumsg(instance_id, platform)
        elif metric_name == 'mem_used_percent' or metric_name ==  'Memory % Committed Bytes In Use':
            email_message = memmsg(instance_id, platform)
        elif metric_name == 'disk_used_percent' or metric_name == 'LogicalDisk % Free Space':
            email_message = diskmsg(instance_id, platform)
        
    except Exception as e:
        email_message = f"An error occured: {str(e)}"
        logger.error(email_message)
    
    return email_message

def lambda_handler(event, context):
    try:
        ec2_client = boto3.client('ec2')
        sns_message = event['Records'][0]['Sns']
        subject = sns_message['Subject']
        message = json.loads(sns_message['Message'])
        state = message['NewStateValue']
        reason = message['NewStateReason']
        timestamp = message['StateChangeTime']
        region = message['Region']
        dimensions = message['Trigger']['Dimensions']
        metric_name = message['Trigger']['MetricName']
            
        timestamp_str = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f+0000").strftime("%A %d %B, %Y %H:%M:%S UTC")
        
        # Checking instance and its platform
        instance_id = None
        for dimension in dimensions:
            if dimension['name'] == 'InstanceId':
                instance_id = dimension['value']
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                platform = response['Reservations'][0]['Instances'][0]['PlatformDetails']
                break
      
        instance_metric = ''
        
        if instance_id:
            instance_metric = instance_metric_details(instance_id, metric_name, platform )
        
        alarm_details = f"Alarm Details:\n- Name: {subject}\n- Timestamp: {timestamp_str}\n- AWS Account: {message['AWSAccountId']}\n- MetricNamespace: {message['Trigger']['Namespace']}\n- MetricName: {message['Trigger']['MetricName']}\n- Dimensions: {message['Trigger']['Dimensions']}\n- Period: {message['Trigger']['Period']} seconds\n- Statistic: {message['Trigger']['Statistic']}\n- Unit: {message['Trigger']['Unit']}\n"
        
        threshold_details = f"Threshold:\n- The alarm is in the {state} state when the metric is {message['Trigger']['ComparisonOperator']} {message['Trigger']['Threshold']} for at least {message['Trigger']['DatapointsToAlarm']} of the last {message['Trigger']['EvaluationPeriods']} period(s) of {message['Trigger']['Period']} seconds."
        
        if instance_metric == '':
            body = f'''
            You are receiving this email because your Amazon CloudWatch Alarm "{subject}" in the {region} region has entered the {state} state, because "{reason}" at "{timestamp_str}.

            {alarm_details}

            {threshold_details}
    
            Regards,
            AWS Alarm
            '''
        else:
            body = f'''

            You are receiving this email because your Amazon CloudWatch Alarm "{subject}" in the {region} region has entered the {state} state, because "{reason}" at "{timestamp_str}".

            {alarm_details}

            {threshold_details}

            {instance_metric}

            Regards,
            AWS Alarm
            '''

        send_email(subject, body)

    #except KeyError as e:
    #    logger.error(f"An error occured: {str(e)}")
    #except json.JSONDecodeError as e:
    #    print(f"JSONDecodeError occurred: {e}")
    except Exception as e:
        logger.error(f"An error occured: {str(e)}")

    return {
        'statusCode': 200,
        'body': json.dumps('Function execution completed successfully!')
    }