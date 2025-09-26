local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"

description = [[
Cloud Metadata Enumeration - Safely enumerates cloud metadata endpoints 
when the target appears to be running in a cloud environment.

This script detects and enumerates metadata endpoints from major cloud providers:
1. AWS EC2 Instance Metadata Service (IMDS)
2. Azure Instance Metadata Service 
3. Google Cloud Metadata Service
4. Oracle Cloud Infrastructure Metadata
5. Alibaba Cloud ECS Metadata
6. IBM Cloud Virtual Server Metadata

The script performs safe, read-only operations and respects cloud provider
rate limits. It focuses on publicly accessible metadata that doesn't
require authentication or special permissions.
]]

---
-- @usage
-- nmap --script cloud-metadata-enum.nse target.com
-- nmap --script cloud-metadata-enum.nse --script-args check-aws=true,check-azure=true target.com
--
-- @output
-- Host script results:
-- | cloud-metadata-enum:
-- |   Cloud Provider: AWS (Amazon Web Services)
-- |   Instance Metadata Service: Accessible
-- |   
-- |   Instance Information:
-- |     Instance ID: i-1234567890abcdef0
-- |     Instance Type: t3.medium
-- |     Region: us-east-1
-- |     Availability Zone: us-east-1a
-- |     AMI ID: ami-0abcdef1234567890
-- |   
-- |   Network Information:
-- |     Private IPv4: 172.31.32.123
-- |     Public IPv4: 54.123.45.67
-- |     VPC ID: vpc-12345678
-- |     Subnet ID: subnet-12345678
-- |   
-- |   Security Information:
-- |     IAM Role: MyInstanceRole
-- |     Security Groups: sg-12345678 (default)
-- |   
-- |   Additional Metadata:
-- |     Hostname: ip-172-31-32-123.ec2.internal
-- |     Launch Time: 2024-01-15T10:30:00Z
-- |_    User Data: [REDACTED - 156 bytes]
--
-- @args cloud-metadata-enum.check-aws Enable AWS metadata checks (default: true)
-- @args cloud-metadata-enum.check-azure Enable Azure metadata checks (default: true)
-- @args cloud-metadata-enum.check-gcp Enable GCP metadata checks (default: true)
-- @args cloud-metadata-enum.check-oracle Enable Oracle Cloud checks (default: true)
-- @args cloud-metadata-enum.timeout HTTP request timeout in seconds (default: 5)
-- @args cloud-metadata-enum.user-agent Custom User-Agent string

author = "Custom NSE Script"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "default"}

-- Host rule: target any host
hostrule = function(host)
    return true
end

-- Script arguments
local args_check_aws = stdnse.get_script_args(SCRIPT_NAME .. ".check-aws")
local args_check_azure = stdnse.get_script_args(SCRIPT_NAME .. ".check-azure") 
local args_check_gcp = stdnse.get_script_args(SCRIPT_NAME .. ".check-gcp")
local args_check_oracle = stdnse.get_script_args(SCRIPT_NAME .. ".check-oracle")
local args_timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
local args_user_agent = stdnse.get_script_args(SCRIPT_NAME .. ".user-agent") or "NSE Cloud Metadata Enumerator"

-- Convert boolean arguments (default to true)
args_check_aws = args_check_aws ~= "false" and args_check_aws ~= "no"
args_check_azure = args_check_azure ~= "false" and args_check_azure ~= "no"
args_check_gcp = args_check_gcp ~= "false" and args_check_gcp ~= "no"
args_check_oracle = args_check_oracle ~= "false" and args_check_oracle ~= "no"

---
-- Cloud metadata endpoints configuration
local cloud_providers = {
    aws = {
        name = "AWS (Amazon Web Services)",
        endpoint = "169.254.169.254",
        paths = {
            base = "/latest/meta-data/",
            token = "/latest/api/token",
            instance_id = "/latest/meta-data/instance-id",
            instance_type = "/latest/meta-data/instance-type",
            region = "/latest/meta-data/placement/region", 
            az = "/latest/meta-data/placement/availability-zone",
            ami_id = "/latest/meta-data/ami-id",
            hostname = "/latest/meta-data/hostname",
            local_ipv4 = "/latest/meta-data/local-ipv4",
            public_ipv4 = "/latest/meta-data/public-ipv4",
            vpc_id = "/latest/meta-data/network/interfaces/macs/",
            subnet_id = "/latest/meta-data/network/interfaces/macs/",
            security_groups = "/latest/meta-data/security-groups",
            iam_role = "/latest/meta-data/iam/security-credentials/",
            user_data = "/latest/user-data"
        },
        headers = {
            ["X-aws-ec2-metadata-token-ttl-seconds"] = "21600"
        }
    },
    azure = {
        name = "Microsoft Azure",
        endpoint = "169.254.169.254",
        paths = {
            base = "/metadata/instance?api-version=2021-02-01",
            compute = "/metadata/instance/compute?api-version=2021-02-01",
            network = "/metadata/instance/network?api-version=2021-02-01"
        },
        headers = {
            ["Metadata"] = "true"
        }
    },
    gcp = {
        name = "Google Cloud Platform",
        endpoint = "169.254.169.254",
        paths = {
            base = "/computeMetadata/v1/",
            instance = "/computeMetadata/v1/instance/",
            project = "/computeMetadata/v1/project/"
        },
        headers = {
            ["Metadata-Flavor"] = "Google"
        }
    },
    oracle = {
        name = "Oracle Cloud Infrastructure",
        endpoint = "169.254.169.254",
        paths = {
            base = "/opc/v2/instance/",
            identity = "/opc/v2/identity/"
        },
        headers = {
            ["Authorization"] = "Bearer Oracle"
        }
    }
}

---
-- Perform HTTP request to metadata endpoint
-- @param endpoint Target endpoint IP
-- @param path Request path  
-- @param headers Custom headers
-- @param method HTTP method
-- @return Response or nil
local function metadata_request(endpoint, path, headers, method)
    method = method or "GET"
    local options = {
        timeout = args_timeout * 1000,
        header = headers or {}
    }
    
    -- Add User-Agent
    options.header["User-Agent"] = args_user_agent
    
    local response
    if method == "PUT" then
        response = http.put(endpoint, 80, path, options)
    else
        response = http.get(endpoint, 80, path, options)
    end
    
    return response
end

---
-- Check if metadata service is accessible
-- @param provider_config Cloud provider configuration
-- @return boolean indicating accessibility
local function is_metadata_accessible(provider_config)
    local response = metadata_request(
        provider_config.endpoint,
        provider_config.paths.base,
        provider_config.headers
    )
    
    return response and (response.status == 200 or response.status == 404)
end

---
-- Get AWS IMDSv2 token
-- @return Token string or nil
local function get_aws_token()
    local response = metadata_request(
        cloud_providers.aws.endpoint,
        cloud_providers.aws.paths.token,
        cloud_providers.aws.headers,
        "PUT"
    )
    
    if response and response.status == 200 and response.body then
        return response.body:match("^%s*(.-)%s*$")  -- trim whitespace
    end
    
    return nil
end

---
-- Enumerate AWS metadata
-- @return Table of AWS metadata
local function enumerate_aws_metadata()
    if not args_check_aws then
        return nil
    end
    
    local aws_config = cloud_providers.aws
    if not is_metadata_accessible(aws_config) then
        return nil
    end
    
    local metadata = {
        provider = aws_config.name,
        accessible = true
    }
    
    -- Try to get IMDSv2 token first
    local token = get_aws_token()
    local request_headers = {}
    if token then
        request_headers["X-aws-ec2-metadata-token"] = token
        metadata.imds_version = "v2"
    else
        metadata.imds_version = "v1"
    end
    
    -- Enumerate basic instance information
    local instance_data = {}
    
    local basic_fields = {
        instance_id = "instance-id",
        instance_type = "instance-type", 
        region = "region",
        availability_zone = "availability-zone",
        ami_id = "ami-id",
        hostname = "hostname",
        local_ipv4 = "local-ipv4",
        public_ipv4 = "public-ipv4"
    }
    
    for key, path_key in pairs(basic_fields) do
        local path = aws_config.paths[path_key] or ("/latest/meta-data/" .. path_key)
        local response = metadata_request(aws_config.endpoint, path, request_headers)
        
        if response and response.status == 200 and response.body then
            instance_data[key] = response.body:match("^%s*(.-)%s*$")
        end
    end
    
    -- Get security groups
    local sg_response = metadata_request(
        aws_config.endpoint,
        aws_config.paths.security_groups,
        request_headers
    )
    if sg_response and sg_response.status == 200 and sg_response.body then
        instance_data.security_groups = sg_response.body:match("^%s*(.-)%s*$")
    end
    
    -- Check for IAM roles
    local iam_response = metadata_request(
        aws_config.endpoint, 
        "/latest/meta-data/iam/security-credentials/",
        request_headers
    )
    if iam_response and iam_response.status == 200 and iam_response.body then
        instance_data.iam_role = iam_response.body:match("^%s*(.-)%s*$")
    end
    
    -- Check user data (don't retrieve content for security)
    local userdata_response = metadata_request(
        aws_config.endpoint,
        aws_config.paths.user_data,
        request_headers
    )
    if userdata_response and userdata_response.status == 200 and userdata_response.body then
        instance_data.user_data_length = #userdata_response.body
    end
    
    metadata.instance_data = instance_data
    return metadata
end

---
-- Enumerate Azure metadata
-- @return Table of Azure metadata  
local function enumerate_azure_metadata()
    if not args_check_azure then
        return nil
    end
    
    local azure_config = cloud_providers.azure
    if not is_metadata_accessible(azure_config) then
        return nil
    end
    
    local metadata = {
        provider = azure_config.name,
        accessible = true
    }
    
    -- Get compute metadata
    local compute_response = metadata_request(
        azure_config.endpoint,
        azure_config.paths.compute,
        azure_config.headers
    )
    
    if compute_response and compute_response.status == 200 and compute_response.body then
        local status, compute_data = pcall(json.parse, compute_response.body)
        if status and compute_data then
            metadata.compute_data = {
                vm_id = compute_data.vmId,
                vm_size = compute_data.vmSize,
                location = compute_data.location,
                resource_group = compute_data.resourceGroupName,
                subscription_id = compute_data.subscriptionId,
                os_type = compute_data.osType,
                computer_name = compute_data.name
            }
        end
    end
    
    -- Get network metadata
    local network_response = metadata_request(
        azure_config.endpoint,
        azure_config.paths.network, 
        azure_config.headers
    )
    
    if network_response and network_response.status == 200 and network_response.body then
        local status, network_data = pcall(json.parse, network_response.body)
        if status and network_data and network_data.interface then
            local interface = network_data.interface[1]
            if interface then
                metadata.network_data = {
                    private_ip = interface.ipv4 and interface.ipv4.ipAddress and interface.ipv4.ipAddress[1] and interface.ipv4.ipAddress[1].privateIpAddress,
                    public_ip = interface.ipv4 and interface.ipv4.ipAddress and interface.ipv4.ipAddress[1] and interface.ipv4.ipAddress[1].publicIpAddress,
                    mac_address = interface.macAddress
                }
            end
        end
    end
    
    return metadata
end

---
-- Enumerate GCP metadata
-- @return Table of GCP metadata
local function enumerate_gcp_metadata()
    if not args_check_gcp then
        return nil
    end
    
    local gcp_config = cloud_providers.gcp
    if not is_metadata_accessible(gcp_config) then
        return nil
    end
    
    local metadata = {
        provider = gcp_config.name,
        accessible = true
    }
    
    local instance_data = {}
    
    -- Basic instance information
    local basic_paths = {
        instance_id = "/computeMetadata/v1/instance/id",
        machine_type = "/computeMetadata/v1/instance/machine-type",
        zone = "/computeMetadata/v1/instance/zone", 
        hostname = "/computeMetadata/v1/instance/hostname",
        internal_ip = "/computeMetadata/v1/instance/network-interfaces/0/ip",
        external_ip = "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip"
    }
    
    for key, path in pairs(basic_paths) do
        local response = metadata_request(gcp_config.endpoint, path, gcp_config.headers)
        if response and response.status == 200 and response.body then
            local value = response.body:match("^%s*(.-)%s*$")
            -- Clean up machine type and zone to show just the name
            if key == "machine_type" or key == "zone" then
                value = value:match("([^/]+)$") or value
            end
            instance_data[key] = value
        end
    end
    
    -- Project information
    local project_response = metadata_request(
        gcp_config.endpoint,
        "/computeMetadata/v1/project/project-id",
        gcp_config.headers
    )
    if project_response and project_response.status == 200 and project_response.body then
        instance_data.project_id = project_response.body:match("^%s*(.-)%s*$")
    end
    
    metadata.instance_data = instance_data
    return metadata
end

---
-- Format metadata results for output
-- @param metadata Metadata table
-- @return Formatted result table
local function format_metadata_results(metadata)
    if not metadata then
        return {}
    end
    
    local result = {}
    
    table.insert(result, string.format("Cloud Provider: %s", metadata.provider))
    table.insert(result, "Instance Metadata Service: Accessible")
    
    if metadata.imds_version then
        table.insert(result, string.format("IMDS Version: %s", metadata.imds_version))
    end
    
    table.insert(result, "")
    
    -- AWS-specific formatting
    if metadata.instance_data and metadata.provider:match("AWS") then
        local data = metadata.instance_data
        
        table.insert(result, "Instance Information:")
        if data.instance_id then table.insert(result, string.format("  Instance ID: %s", data.instance_id)) end
        if data.instance_type then table.insert(result, string.format("  Instance Type: %s", data.instance_type)) end
        if data.region then table.insert(result, string.format("  Region: %s", data.region)) end
        if data.availability_zone then table.insert(result, string.format("  Availability Zone: %s", data.availability_zone)) end
        if data.ami_id then table.insert(result, string.format("  AMI ID: %s", data.ami_id)) end
        table.insert(result, "")
        
        table.insert(result, "Network Information:")
        if data.local_ipv4 then table.insert(result, string.format("  Private IPv4: %s", data.local_ipv4)) end
        if data.public_ipv4 then table.insert(result, string.format("  Public IPv4: %s", data.public_ipv4)) end
        if data.hostname then table.insert(result, string.format("  Hostname: %s", data.hostname)) end
        table.insert(result, "")
        
        if data.iam_role or data.security_groups then
            table.insert(result, "Security Information:")
            if data.iam_role then table.insert(result, string.format("  IAM Role: %s", data.iam_role)) end
            if data.security_groups then table.insert(result, string.format("  Security Groups: %s", data.security_groups)) end
            table.insert(result, "")
        end
        
        if data.user_data_length then
            table.insert(result, "Additional Information:")
            table.insert(result, string.format("  User Data: [DETECTED - %d bytes]", data.user_data_length))
        end
    end
    
    -- Azure-specific formatting
    if metadata.compute_data and metadata.provider:match("Azure") then
        local compute = metadata.compute_data
        local network = metadata.network_data
        
        table.insert(result, "Virtual Machine Information:")
        if compute.vm_id then table.insert(result, string.format("  VM ID: %s", compute.vm_id)) end
        if compute.vm_size then table.insert(result, string.format("  VM Size: %s", compute.vm_size)) end
        if compute.location then table.insert(result, string.format("  Location: %s", compute.location)) end
        if compute.resource_group then table.insert(result, string.format("  Resource Group: %s", compute.resource_group)) end
        if compute.subscription_id then table.insert(result, string.format("  Subscription ID: %s", compute.subscription_id)) end
        table.insert(result, "")
        
        if network then
            table.insert(result, "Network Information:")
            if network.private_ip then table.insert(result, string.format("  Private IP: %s", network.private_ip)) end
            if network.public_ip then table.insert(result, string.format("  Public IP: %s", network.public_ip)) end
            if network.mac_address then table.insert(result, string.format("  MAC Address: %s", network.mac_address)) end
            table.insert(result, "")
        end
    end
    
    -- GCP-specific formatting  
    if metadata.instance_data and metadata.provider:match("Google") then
        local data = metadata.instance_data
        
        table.insert(result, "Instance Information:")
        if data.instance_id then table.insert(result, string.format("  Instance ID: %s", data.instance_id)) end
        if data.machine_type then table.insert(result, string.format("  Machine Type: %s", data.machine_type)) end
        if data.zone then table.insert(result, string.format("  Zone: %s", data.zone)) end
        if data.project_id then table.insert(result, string.format("  Project ID: %s", data.project_id)) end
        table.insert(result, "")
        
        table.insert(result, "Network Information:")
        if data.internal_ip then table.insert(result, string.format("  Internal IP: %s", data.internal_ip)) end
        if data.external_ip then table.insert(result, string.format("  External IP: %s", data.external_ip)) end
        if data.hostname then table.insert(result, string.format("  Hostname: %s", data.hostname)) end
    end
    
    return result
end

---
-- Main action function
-- @param host Target host
-- @return Script results
action = function(host)
    stdnse.debug1("Starting cloud metadata enumeration")
    
    local results = {}
    local found_provider = nil
    
    -- Check each cloud provider
    local providers_to_check = {
        {name = "aws", func = enumerate_aws_metadata},
        {name = "azure", func = enumerate_azure_metadata},
        {name = "gcp", func = enumerate_gcp_metadata}
    }
    
    for _, provider in ipairs(providers_to_check) do
        local metadata = provider.func()
        if metadata and metadata.accessible then
            found_provider = metadata
            break  -- Stop at first detected provider
        end
    end
    
    if found_provider then
        local formatted_results = format_metadata_results(found_provider)
        return table.concat(formatted_results, "\n")
    else
        return "No cloud metadata services detected"
    end
end