rule Hackathon_Custom_Test_String {
    meta:
        author = "Pipeline Admin"
        description = "Custom test string to bypass Gmail AV but trigger our pipeline"
        risk_level = "High"
    strings:
        $custom_string = "HACKATHON_MALWARE_SIMULATION_99887766"
    condition:
        $custom_string
}

rule Suspicious_MZ_Header {
    meta:
        author = "Pipeline Admin"
        description = "Detects Windows Executable (PE) format"
        risk_level = "Medium"
    strings:
        $mz = "MZ"
    condition:
        $mz at 0
}