from sentinel.scanners.security_groups import check_security_group


def make_sg(port, cidr="0.0.0.0/0", group_id="sg-test", group_name="test-sg"):
    return {
        "GroupId": group_id,
        "GroupName": group_name,
        "IpPermissions": [
            {
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": cidr}],
            }
        ],
    }


def test_ssh_open_to_world_is_flagged():
    sg = make_sg(port=22)
    findings = check_security_group(sg, region="us-east-1")
    assert len(findings) == 1
    assert findings[0].finding_id == "SG-001"
    assert findings[0].severity == "CRITICAL"


def test_rdp_open_to_world_is_flagged():
    sg = make_sg(port=3389)
    findings = check_security_group(sg, region="us-east-1")
    assert len(findings) == 1
    assert findings[0].evidence["service"] == "RDP"


def test_ssh_restricted_to_specific_cidr_not_flagged():
    sg = make_sg(port=22, cidr="10.0.0.0/24")
    findings = check_security_group(sg, region="us-east-1")
    assert findings == []


def test_non_dangerous_port_open_to_world_not_flagged():
    sg = make_sg(port=8080)
    findings = check_security_group(sg, region="us-east-1")
    assert findings == []


def test_full_port_range_open_to_world_flags_all_dangerous_ports():
    sg = {
        "GroupId": "sg-test",
        "GroupName": "test-sg",
        "IpPermissions": [
            {"FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
        ],
    }
    findings = check_security_group(sg, region="us-east-1")
    # All 6 dangerous ports (22, 3389, 3306, 5432, 1433, 27017) fall within 0-65535
    assert len(findings) == 6