# This script created by Century College for the automated triage and/or analysis of potential malware samples. 2015-2016.

# Currently the script utilizes "swftools", "python-magic", "yara", and "oletools". Please ensure that these programs and/or modules are installed prior to execution.
# In Windows, you may install yara, oletools and python-magic using PIP. You will also need to have swftools installed within windows, and their path added to your Windows environment execution path.
# pip install yara
# pip install oletools
# pip install python-magic

try:
    import os
    import sys
    import subprocess
    import hashlib
    import base64
    import time

    import yara
    import magic
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
except ImportError:
    sys.exit("--:--  Missing Python Module. This script requires the yara, magic, and oletools Python modules to run. Please install them and try again.")

def _setup(b64e_yara):

    # Create target list/dir and output dir.
    orig_path = str(os.path.expanduser('~')+'/automal_input')
    if not os.path.exists(orig_path):
        os.makedirs(orig_path)
    orig_target_list = os.listdir(orig_path)
    full_targ_list = []
    for targ in orig_target_list:
         full_targ_list.append(orig_path+"/"+targ)

    out_path = str(os.path.expanduser('~')+'/automal_output')
    if not os.path.exists(out_path):
        os.makedirs(out_path)
    
    # QA
    if not os.path.exists(str(os.path.expanduser('~'))+'/automal'):
        os.makedirs(str(os.path.expanduser('~'))+'/automal')
    
    # This script urilizes two yara rules as part of it's "analysis", we need to decode the hardcoded yara rules and save them out to the tmp directory.
    b64e_data_maldoc = b64e_yara.split(':')[0]
    b64e_data_pe = b64e_yara.split(':')[1]
    b64e_data_obf = b64e_yara.split(':')[2]

    b64d_data_maldoc =  base64.b64decode(b64e_data_maldoc)
    b64d_data_pe = base64.b64decode(b64e_data_pe)
    b64d_data_obf = base64.b64decode(b64e_data_obf)

    if not os.path.exists(str(os.path.expanduser('~'))+'/automal/contains_pe_file.yara'):
        yara_file1 = open(str(os.path.expanduser('~'))+'/automal/contains_pe_file.yara', 'w')
        yara_file1.write(b64d_data_pe)
        yara_file1.close()

    if not os.path.exists(str(os.path.expanduser('~'))+'/automal/maldoc.yara'):
        yara_file2 = open(str(os.path.expanduser('~'))+'/automal/maldoc.yara', 'w')
        yara_file2.write(b64d_data_maldoc)
        yara_file2.close()

    if not os.path.exists(str(os.path.expanduser('~'))+'/automal/obfus_strings.yara'):
        yara_file3 = open(str(os.path.expanduser('~'))+'/automal/obfus_strings.yara', 'w')
        yara_file3.write(b64d_data_obf)
        yara_file3.close()

    return(orig_path, orig_target_list, full_targ_list, out_path)

def _get_file_type(full_targ_path):
    # This function takes the full path of a target sample and determines/returns the file type via python-magic.
    try:
        #magicObj = magic.open(magic.MAGIC_NONE)
        #magicObj.load()
        #magic_out = str(magicObj.file(full_targ_path))
		magicObj = magic.Magic(magic_file=r'C:/Program Files (x86)/GnuWin32/share/misc/magic', mime=True)
		magic_out = str(magicObj.from_file(full_targ_path))
		print magic_out
    except AttributeError:
        magic_out = str(magic.from_file(full_targ_path))
        print magic_out+" ERROR?!?!?!!?"

    return(magic_out)

def _swf_analysis(full_targ_path):
    # This function calls swftools, tools, and flasm against SWF samples to extract data and/or performs analysis as needed.
    command_out = subprocess.Popen(["swfdump", "-a", full_targ_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    command2_out = subprocess.Popen(["swfextract", full_targ_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0]
    command2_list = command2_out.split('\n')
    command_out_list = command_out.split('\n')
    
    swf_ioc_res = ""

    for out in command_out_list:
        strOut = str(out)
        ioc_list = ["http", "www", ".com", ".net", ".info", "GetVariable", "GetURL", 'String:"_post"', 'String:"send"', "\\\\", "pushstring", "url.split", ".php", "urlmon", ".exe"]
        for indi in ioc_list:
            if indi in strOut:
                if ":::Present_"+indi not in swf_ioc_res:
                    swf_ioc_res += ":::Present_"+indi

    if len(swf_ioc_res) == 0:
        swf_ioc_res = "None"

    extract_list_fns = []
    for out in command2_list:
        if "JPEG" in out:
            j_id = out.rfind(' ')+1
            j_id = int(out[j_id:len(out)])
            # Sometimes picture extraction doesn't occur... correctly, so we suppress the output. If we get it, great, if we don't whatever, for now.
            os_null = open(os.devnull, 'wb')
            subprocess.Popen(['swfextract', full_targ_path, '-j', str(j_id), '-o', str(os.path.expanduser('~'))+'/automal/'+str(j_id)+'.jpg'], stdout=os_null, stderr=os_null)
            subprocess.Popen(['swfextract', full_targ_path, '-p', str(j_id), '-o', str(os.path.expanduser('~'))+'/automal/'+str(j_id)+'.png'], stdout=os_null, stderr=os_null)
            extract_list_fns.append(str(os.path.expanduser('~'))+'/automal/'+str(j_id))
    return(command_out, extract_list_fns, command2_out, swf_ioc_res)

def _ole_analysis(full_targ_path):
    # This function calls a number of tools / scripts to run against document samples containing OLE data and extracts data and/or performs analysis as needed.
    try:
        vba_parse_Obj = VBA_Parser(full_targ_path)
    except AttributeError:
        return("ERROR_PARSING", "ERROR_PARSING", "ERROR_PARSING", "ERROR_PARSING")
    macro_analysis_over = []
    macro_analysis_info = []
    if vba_parse_Obj.detect_vba_macros():
        vba_macro = "Present"
        # Utilizing oletools to perform analysis.

        # Grabbing info from each macro.
        MA_CNT = 1
        for (file_name, ole_stream, vba_filename, vba_code) in vba_parse_Obj.extract_macros():
            macro_analysis_over.append(str(MA_CNT)+':'+str(full_targ_path))
            macro_analysis_over.append(str(MA_CNT)+":Filename      :"+file_name)
            macro_analysis_over.append(str(MA_CNT)+":OLE Stream    :"+ole_stream)
            macro_analysis_over.append(str(MA_CNT)+":VBA Filename  :"+vba_filename)
            macro_analysis_over.append(str(MA_CNT)+':'+vba_code)
            MA_CNT+=1

        # Grabbing some overall VBA analysis info.
        macro_flag_types = []
        macro_analysis_res = vba_parse_Obj.analyze_macros()
        if isinstance(macro_analysis_res, list):
            for iocType in macro_analysis_res:
                if str(iocType) not in macro_flag_types:
                    macro_flag_types.append(str(iocType[0]))


        if len(macro_flag_types) > 0:
            iocs = ':'.join(list(set(macro_flag_types)))
        else:
            iocs = "None"

    else:
        vba_macro = "None"
        iocs = "None"
        macro_analysis_res = "None"

    vba_parse_Obj.close()

    return(vba_macro, macro_analysis_over, str(macro_analysis_res), iocs)

def _c_sample_out_dir(targ, automal_dir):
    # When we analyze samples, a output directory named after the MD5 hash of the sample is created and/or used for the samples specific exports, putput info, etc.
    out_md5 = str(hashlib.md5(targ).hexdigest())
    out_full_path = automal_dir+'/'+out_md5
    if not os.path.exists(out_full_path):
        os.makedirs(out_full_path)
    out_file_Obj = open(out_full_path+'/Output.txt', 'a')
    return (out_file_Obj, out_full_path, out_md5)

def _yara_check(targ):
    # Utilize  yara rules packed into this script to check for nasty stuff. Compile each rule stored in tmp and check the rule_match results for a Match True hit.
    
# -------------------------------------- RULE 1    

    contains_pe_file_rule = yara.compile(filepath=str(os.path.expanduser('~'))+'/automal/contains_pe_file.yara')
    match_pe = contains_pe_file_rule.match(targ)
    yara_pe_res = ""
    if len(match_pe) == 1:
        match_data_pe = str(match_pe).split(',')
        for item in match_data_pe:
            if "True" in item.strip() and "matches" in item.strip():
                yara_pe_res = "Present_PE_Hit"
        if yara_pe_res != "Present_PE_Hit":
            yara_pe_res = "PE_None"
    else:
        if yara_pe_res != "Present_PE_Hit":
            yara_pe_res = "PE_None"

# -------------------------------------- RULE 2

    maldoc_file_rule = yara.compile(filepath=str(os.path.expanduser('~'))+'/automal/maldoc.yara')
    match_maldoc = maldoc_file_rule.match(targ)
    yara_maldoc_res = ""
    if len(match_maldoc) == 1:
        match_data_maldoc = str(match_maldoc).split(',')
        for item in match_data_maldoc:
            if "True" in item.strip() and "matches" in item.strip():
                yara_maldoc_res = "Present_Maldoc_Hit"
        if yara_maldoc_res != "Present_Maldoc_Hit":
            yara_maldoc_res = "Maldoc_None"
    else:
        if yara_maldoc_res != "Present_Maldoc_Hit":
            yara_maldoc_res = "Maldoc_None"

# ------------------------------------- RULE 3

    contains_obfus_str = yara.compile(filepath=str(os.path.expanduser('~'))+'/automal/obfus_strings.yara')
    match_obf = contains_obfus_str.match(targ)
    yara_obf_res = ""
    if len(match_obf) == 1:
        match_data_obfus = str(match_obf).split(',')
        for item in match_data_obfus:
            if "True" in item.strip() and "matches" in item.strip():
                yara_obf_res = "Present_Obfus_Hit"
        if yara_obf_res != "Present_Obfus_Hit":
            yara_obf_res = "Obfus_None"
    else:
        if yara_obf_res != "Present_Obfus_Hit":
            yara_obf_res = "Obfus_None"

    return(yara_pe_res, yara_maldoc_res, yara_obf_res)

def _core(b64e_yara):
    sample_counter = 0
    # This function brings it all together, does some thinking, and acts accordingly.
    run_data = _setup(b64e_yara)

    print "-- : --  Processing samples..."
    
    # Setup the automal output directory.
    automal_dir = str(run_data[3])+'/automal_output'
    if not os.path.exists(automal_dir):
        os.makedirs(automal_dir)

    # Setup processed sample destination dir.
    mv_path = str(automal_dir+'/processed_samples/'+time.strftime('%m_%d_%y_%H_%M_%S/'))
    if not os.path.exists(mv_path):
        os.makedirs(mv_path)


    # Create and add header line to master output csv file.
    if not os.path.exists(automal_dir+'/Master_Output_Table_'+time.strftime('%m_%d_%y_%H_%M_%S')+'.csv'):
        master_out = open(automal_dir+'/Master_Output_Table_'+time.strftime('%m_%d_%y_%H_%M_%S')+'.csv', 'a')
        master_out.write('File Name, MD5 Hash, File Type, OLE-VB Macro Present, Yara Signature Hit, IOC Present,\n')
    else:
        master_out = open(automal_dir+'/Master_Output_Table_'+time.strftime('%m_%d_%y_%H_%M_%S')+'.csv', 'a')

    # We need to create a directory for all processed samples to be moved to.
    if not os.path.exists(automal_dir+'/processed_samples'):
        processed_samples_dir = os.makedirs(automal_dir+'/processed_samples')

    # We use this for Popen suppression.
    os_null = open(os.devnull, 'wb')

    # This for loop gets the type of each sample via magic, and then runs functions and/or other analysis against the samples and commits result data accordingly.
    for targ in run_data[2]:
        f_type = _get_file_type(targ)
        print "[ + ] : "+str(targ[targ.rfind('/')+1:len(targ)])

# ---------------------------------------------
# -------------------- SWF --------------------
# ---------------------------------------------

        if "shockwave-flash" in f_type:
            swf_res = _swf_analysis(targ)

            out_file_info = _c_sample_out_dir(targ, automal_dir)

            out_file_Obj = out_file_info[0]
            out_file_Obj.write(targ+"\n"+str(swf_res[0])+"\n")
            out_file_Obj.write(targ+"\n"+str(swf_res[2])+"\n")
            out_file_Obj.close()

            # Sometimes when we don't get the pictures we tried to extract, or if they don't exist because we just guess extension, etc, we want to suppress error/output stuff. For now.
            for tmpFile in swf_res[1]:
                subprocess.Popen(['mv', tmpFile+'.png', out_file_info[1]], stdout=os_null, stderr=os_null)
                subprocess.Popen(['mv', tmpFile+'.jpg', out_file_info[1]], stdout=os_null, stderr=os_null)

            yara_pe_res = _yara_check(targ)[0]
            yara_maldoc_res = _yara_check(targ)[1]
            yara_obf_res = _yara_check(targ)[2]

            master_out.write(str(targ[targ.rfind('/')+1:len(targ)])+','+str(out_file_info[2])+',SWF,NA,'+str(yara_maldoc_res)+':::'+str(yara_pe_res)+':::'+str(yara_obf_res)+','+str(swf_res[3])+',\n')
            out_file_info[0].close()

# ---------------------------------------------
# -------------------- OLE --------------------
# ---------------------------------------------

        if "ms-excel" in f_type or "msword" in f_type or targ.endswith(".doc") or targ.endswith(".docx"):
            ole_res = _ole_analysis(targ)
            
            out_file_info = _c_sample_out_dir(targ, automal_dir)
            out_file_Obj = out_file_info[0]
            out_file_Obj.write(targ+"\n")
            for line in ole_res[1]:
                try:
                    out_file_Obj.write(line+"\n")
                except UnicodeEncodeError:
                    out_file_Obj.write("UNICODE ENCODE ERROR")

            out_file_Obj.write(str(ole_res[2])+"\n")
            
            yara_pe_res = _yara_check(targ)[0]
            yara_maldoc_res = _yara_check(targ)[1]
            yara_obf_res = _yara_check(targ)[2]

            master_out.write(str(targ[targ.rfind('/')+1:len(targ)])+','+str(out_file_info[2])+',OLE,'+str(ole_res[0])+','+str(yara_maldoc_res)+':::'+str(yara_pe_res)+':::'+str(yara_obf_res)+','+str(ole_res[3])+',\n')
            out_file_info[0].close()
        
        subprocess.Popen(['mv', targ, mv_path], stdout=os_null, stderr=os_null)
        sample_counter += 1

    print "-- : -- Processed "+str(sample_counter)+" total samples."
    print "-- : -- Finished."
    master_out.close()

b64e_yara = "LyoNCiAgVmVyc2lvbiAwLjAuMiAyMDE0LzEyLzE2DQogIFNvdXJjZSBjb2RlIHB1dCBpbiBwdWJsaWMgZG9tYWluIGJ5IERpZGllciBTdGV2ZW5zLCBubyBDb3B5cmlnaHQNCiAgaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbQ0KICBVc2UgYXQgeW91ciBvd24gcmlzaw0KDQogIFRoZXNlIGFyZSBZQVJBIHJ1bGVzIHRvIGRldGVjdCBzaGVsbGNvZGUsIHRyYW5zbGF0ZWQgZnJvbSBYT1JTZWFyY2gncyB3aWxkY2FyZCBydWxlcywNCiAgd2hpY2ggdGhlbXNlbHZlcyB3ZXJlIGRldmVsb3BlZCBiYXNlZCBvbiBGcmFuayBCb2xkZXdpbidzIHNoZWxsY29kZSBkZXRlY3RvciB1c2VkIGluIE9mZmljZU1hbFNjYW5uZXIuDQoNCiAgU2hvcnRjb21pbmdzLCBvciB0b2RvJ3MgOy0pIDoNCiAgICBSZW1haW5pbmcgWE9SU2VhcmNoIHdpbGRjYXJkIHJ1bGVzOg0KICAgICAgR2V0RUlQIG1ldGhvZCAyOjEwOkVCKEo7MSlFOChKOzQpKEI7MDEwMTE/Pz8pDQogICAgICBHZXRFSVAgbWV0aG9kIDM6MTA6RTkoSjs0KUU4KEo7NCkoQjswMTAxMT8/PykNCg0KICBIaXN0b3J5Og0KICAgIDIwMTQvMTIvMTU6IHN0YXJ0DQogICAgMjAxNC8xMi8xNjogZXh0cmEgZG9jdW1lbnRhdGlvbg0KKi8NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEFQSSBIYXNoaW5nOjEwOkFDODRDMDc0MDdDMUNGMEQwMUM3RUJGNDgxRkYNCiAgICBBUEkgSGFzaGluZyBiaXM6MTA6QUM4NEMwNzQwN0MxQ0YwNzAxQzdFQkY0ODFGRg0KKi8NCnJ1bGUgbWFsZG9jX0FQSV9oYXNoaW5nDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7QUMgODQgQzAgNzQgMDcgQzEgQ0YgMEQgMDEgQzcgRUIgRjQgODEgRkZ9DQogICAgICAgICRhMiA9IHtBQyA4NCBDMCA3NCAwNyBDMSBDRiAwNyAwMSBDNyBFQiBGNCA4MSBGRn0NCiAgICBjb25kaXRpb246DQogICAgICAgIGFueSBvZiB0aGVtDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBGdW5jdGlvbiBwcm9sb2cgc2lnbmF0dXJlOjEwOjU1OEJFQzgzQzQNCiAgICBGdW5jdGlvbiBwcm9sb2cgc2lnbmF0dXJlOjEwOjU1OEJFQzgxRUMNCiAgICBGdW5jdGlvbiBwcm9sb2cgc2lnbmF0dXJlOjEwOjU1OEJFQ0VCDQogICAgRnVuY3Rpb24gcHJvbG9nIHNpZ25hdHVyZToxMDo1NThCRUNFOA0KICAgIEZ1bmN0aW9uIHByb2xvZyBzaWduYXR1cmU6MTA6NTU4QkVDRTkNCiovDQpydWxlIG1hbGRvY19mdW5jdGlvbl9wcm9sb2dfc2lnbmF0dXJlDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7NTUgOEIgRUMgODEgRUN9DQogICAgICAgICRhMiA9IHs1NSA4QiBFQyA4MyBDNH0NCiAgICAgICAgJGEzID0gezU1IDhCIEVDIEU4fQ0KICAgICAgICAkYTQgPSB7NTUgOEIgRUMgRTl9DQogICAgICAgICRhNSA9IHs1NSA4QiBFQyBFQn0NCiAgICBjb25kaXRpb246DQogICAgICAgIGFueSBvZiB0aGVtDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBTdHJ1Y3R1cmVkIGV4Y2VwdGlvbiBoYW5kbGluZyA6MTA6NjQ4QihCOzAwPz8/MTAxKTAwMDAwMDAwDQogICAgU3RydWN0dXJlZCBleGNlcHRpb24gaGFuZGxpbmcgYmlzOjEwOjY0QTEwMDAwMDAwMA0KKi8NCnJ1bGUgbWFsZG9jX3N0cnVjdHVyZWRfZXhjZXB0aW9uX2hhbmRsaW5nDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7NjQgOEIgKDA1fDBEfDE1fDFEfDI1fDJEfDM1fDNEKSAwMCAwMCAwMCAwMH0NCiAgICAgICAgJGEyID0gezY0IEExIDAwIDAwIDAwIDAwfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgYW55IG9mIHRoZW0NCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEluZGlyZWN0IGZ1bmN0aW9uIGNhbGw6MTA6RkY3NShCO0E/Pz8/Pz8/KUZGNTUoQjtBPz8/Pz8/PykNCiovDQpydWxlIG1hbGRvY19pbmRpcmVjdF9mdW5jdGlvbl9jYWxsXzENCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhID0ge0ZGIDc1ID8/IEZGIDU1ID8/fQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgZm9yIGFueSBpIGluICgxLi4jYSk6ICh1aW50OChAYVtpXSArIDIpID09IHVpbnQ4KEBhW2ldICsgNSkpDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBJbmRpcmVjdCBmdW5jdGlvbiBjYWxsIGJpczoxMDpGRkI1KEI7QT8/Pz8/Pz8pKEI7Qj8/Pz8/Pz8pKEI7Qz8/Pz8/Pz8pKEI7RD8/Pz8/Pz8pRkY5NShCO0E/Pz8/Pz8/KShCO0I/Pz8/Pz8/KShCO0M/Pz8/Pz8/KShCO0Q/Pz8/Pz8/KQ0KKi8NCnJ1bGUgbWFsZG9jX2luZGlyZWN0X2Z1bmN0aW9uX2NhbGxfMg0Kew0KICAgIG1ldGE6DQogICAgICAgIGF1dGhvciA9ICJEaWRpZXIgU3RldmVucyAoaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbSkiDQogICAgc3RyaW5nczoNCiAgICAgICAgJGEgPSB7RkYgQjUgPz8gPz8gPz8gPz8gRkYgOTUgPz8gPz8gPz8gPz99DQogICAgY29uZGl0aW9uOg0KICAgICAgICBmb3IgYW55IGkgaW4gKDEuLiNhKTogKCh1aW50OChAYVtpXSArIDIpID09IHVpbnQ4KEBhW2ldICsgOCkpIGFuZCAodWludDgoQGFbaV0gKyAzKSA9PSB1aW50OChAYVtpXSArIDkpKSBhbmQgKHVpbnQ4KEBhW2ldICsgNCkgPT0gdWludDgoQGFbaV0gKyAxMCkpIGFuZCAodWludDgoQGFbaV0gKyA1KSA9PSB1aW50OChAYVtpXSArIDExKSkpDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBJbmRpcmVjdCBmdW5jdGlvbiBjYWxsIHRyaXM6MTA6RkZCNyhCOz8/Pz8/Pz8/KShCOz8/Pz8/Pz8/KShCOz8/Pz8/Pz8/KShCOz8/Pz8/Pz8/KUZGNTcoQjs/Pz8/Pz8/PykNCiovDQpydWxlIG1hbGRvY19pbmRpcmVjdF9mdW5jdGlvbl9jYWxsXzMNCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhID0ge0ZGIEI3ID8/ID8/ID8/ID8/IEZGIDU3ID8/fQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgJGENCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEZpbmQga2VybmVsMzIgYmFzZSBtZXRob2QgMToxMDo2NDhCKEI7MDA/Pz8xMDEpMzAwMDAwMDANCiAgICBGaW5kIGtlcm5lbDMyIGJhc2UgbWV0aG9kIDFiaXM6MTA6NjRBMTMwMDAwMDAwDQoqLw0KcnVsZSBtYWxkb2NfZmluZF9rZXJuZWwzMl9iYXNlX21ldGhvZF8xDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7NjQgOEIgKDA1fDBEfDE1fDFEfDI1fDJEfDM1fDNEKSAzMCAwMCAwMCAwMH0NCiAgICAgICAgJGEyID0gezY0IEExIDMwIDAwIDAwIDAwfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgYW55IG9mIHRoZW0NCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEZpbmQga2VybmVsMzIgYmFzZSBtZXRob2QgMjoxMDozMShCOzExQT8/QT8/KShCOzEwMTAwQT8/KTMwNjQ4QihCOzAwQj8/QT8/KQ0KKi8NCnJ1bGUgbWFsZG9jX2ZpbmRfa2VybmVsMzJfYmFzZV9tZXRob2RfMg0Kew0KICAgIG1ldGE6DQogICAgICAgIGF1dGhvciA9ICJEaWRpZXIgU3RldmVucyAoaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbSkiDQogICAgc3RyaW5nczoNCiAgICAgICAgJGEgPSB7MzEgPz8gPz8gMzAgNjQgOEIgPz99DQogICAgY29uZGl0aW9uOg0KICAgICAgICBmb3IgYW55IGkgaW4gKDEuLiNhKTogKCh1aW50OChAYVtpXSArIDEpID49IDB4QzApIGFuZCAoKCh1aW50OChAYVtpXSArIDEpICYgMHgzOCkgPj4gMykgPT0gKHVpbnQ4KEBhW2ldICsgMSkgJiAweDA3KSkgYW5kICgodWludDgoQGFbaV0gKyAyKSAmIDB4RjgpID09IDB4QTApIGFuZCAodWludDgoQGFbaV0gKyA2KSA8PSAweDNGKSBhbmQgKCgodWludDgoQGFbaV0gKyA2KSAmIDB4MzgpID4+IDMpICE9ICh1aW50OChAYVtpXSArIDYpICYgMHgwNykpKQ0KfQ0KDQovKg0KWE9SU2VhcmNoIHdpbGRjYXJkIHJ1bGUocyk6DQogICAgRmluZCBrZXJuZWwzMiBiYXNlIG1ldGhvZCAzOjEwOjY4MzAwMDAwMDAoQjswMTAxMUE/Pyk2NDhCKEI7MDBCPz9BPz8pDQoqLw0KcnVsZSBtYWxkb2NfZmluZF9rZXJuZWwzMl9iYXNlX21ldGhvZF8zDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYSA9IHs2OCAzMCAwMCAwMCAwMCAoNTh8NTl8NUF8NUJ8NUN8NUR8NUV8NUYpIDY0IDhCID8/fQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgZm9yIGFueSBpIGluICgxLi4jYSk6ICgoKHVpbnQ4KEBhW2ldICsgNSkgJiAweDA3KSA9PSAodWludDgoQGFbaV0gKyA4KSAmIDB4MDcpKSBhbmQgKHVpbnQ4KEBhW2ldICsgOCkgPD0gMHgzRikgYW5kICgoKHVpbnQ4KEBhW2ldICsgOCkgJiAweDM4KSA+PiAzKSAhPSAodWludDgoQGFbaV0gKyA4KSAmIDB4MDcpKSkNCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEdldEVJUCBtZXRob2QgMToxMDpFODAwMDAwMDAwKEI7MDEwMTE/Pz8pDQoqLw0KcnVsZSBtYWxkb2NfZ2V0RUlQX21ldGhvZF8xDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYSA9IHtFOCAwMCAwMCAwMCAwMCAoNTh8NTl8NUF8NUJ8NUN8NUR8NUV8NUYpfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgJGENCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEdldEVJUCBtZXRob2QgNCBGTERaL0ZTVEVOViBbZXNwLTEyXToxMDpEOUVFRDk3NDI0RjQoQjswMTAxMT8/PykNCiAgICBHZXRFSVAgbWV0aG9kIDQ6MTA6RDlFRTlCRDk3NDI0RjQoQjswMTAxMT8/PykNCiovDQpydWxlIG1hbGRvY19nZXRFSVBfbWV0aG9kXzQNCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhMSA9IHtEOSBFRSBEOSA3NCAyNCBGNCAoNTh8NTl8NUF8NUJ8NUN8NUR8NUV8NUYpfQ0KICAgICAgICAkYTIgPSB7RDkgRUUgOUIgRDkgNzQgMjQgRjQgKDU4fDU5fDVBfDVCfDVDfDVEfDVFfDVGKX0NCiAgICBjb25kaXRpb246DQogICAgICAgIGFueSBvZiB0aGVtDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBPTEUgZmlsZSBtYWdpYyBudW1iZXI6MTA6RDBDRjExRTANCiovDQpydWxlIG1hbGRvY19PTEVfZmlsZV9tYWdpY19udW1iZXINCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhID0ge0QwIENGIDExIEUwfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgJGENCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1VcmxEb3dubG9hZFRvRmlsZQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1HZXRUZW1wUGF0aA0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1HZXRXaW5kb3dzRGlyZWN0b3J5DQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPUdldFN5c3RlbURpcmVjdG9yeQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1XaW5FeGVjDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPVNoZWxsRXhlY3V0ZQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1Jc0JhZFJlYWRQdHINCiAgICBTdXNwaWNpb3VzIHN0cmluZ3M6MjpzdHI9SXNCYWRXcml0ZVB0cg0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1DcmVhdGVGaWxlDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPUNsb3NlSGFuZGxlDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPVJlYWRGaWxlDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPVdyaXRlRmlsZQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1TZXRGaWxlUG9pbnRlcg0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1WaXJ0dWFsQWxsb2MNCiAgICBTdXNwaWNpb3VzIHN0cmluZ3M6MjpzdHI9R2V0UHJvY0FkZHINCiAgICBTdXNwaWNpb3VzIHN0cmluZ3M6MjpzdHI9TG9hZExpYnJhcnkNCiovDQpydWxlIG1hbGRvY19zdXNwaWNpb3VzX3N0cmluZ3MNCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhMDEgPSAiQ2xvc2VIYW5kbGUiDQogICAgICAgICRhMDIgPSAiQ3JlYXRlRmlsZSINCiAgICAgICAgJGEwMyA9ICJHZXRQcm9jQWRkciINCiAgICAgICAgJGEwNCA9ICJHZXRTeXN0ZW1EaXJlY3RvcnkiDQogICAgICAgICRhMDUgPSAiR2V0VGVtcFBhdGgiDQogICAgICAgICRhMDYgPSAiR2V0V2luZG93c0RpcmVjdG9yeSINCiAgICAgICAgJGEwNyA9ICJJc0JhZFJlYWRQdHIiDQogICAgICAgICRhMDggPSAiSXNCYWRXcml0ZVB0ciINCiAgICAgICAgJGEwOSA9ICJMb2FkTGlicmFyeSINCiAgICAgICAgJGExMCA9ICJSZWFkRmlsZSINCiAgICAgICAgJGExMSA9ICJTZXRGaWxlUG9pbnRlciINCiAgICAgICAgJGExMiA9ICJTaGVsbEV4ZWN1dGUiDQogICAgICAgICRhMTMgPSAiVXJsRG93bmxvYWRUb0ZpbGUiDQogICAgICAgICRhMTQgPSAiVmlydHVhbEFsbG9jIg0KICAgICAgICAkYTE1ID0gIldpbkV4ZWMiDQogICAgICAgICRhMTYgPSAiV3JpdGVGaWxlIg0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgYW55IG9mIHRoZW0NCn0NCg=="
b64e_yara += ":LyoNCiAgVmVyc2lvbiAwLjAuMSAyMDE0LzEyLzEzDQogIFNvdXJjZSBjb2RlIHB1dCBpbiBwdWJsaWMgZG9tYWluIGJ5IERpZGllciBTdGV2ZW5zLCBubyBDb3B5cmlnaHQNCiAgaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbQ0KICBVc2UgYXQgeW91ciBvd24gcmlzaw0KDQogIFNob3J0Y29taW5ncywgb3IgdG9kbydzIDstKSA6DQoNCiAgSGlzdG9yeToNCiAgICAyMDE0LzEyLzEzOiBzdGFydA0KICAgIDIwMTQvMTIvMTU6IGRvY3VtZW50YXRpb24NCiovDQoNCnJ1bGUgQ29udGFpbnNfUEVfRmlsZQ0Kew0KICAgIG1ldGE6DQogICAgICAgIGF1dGhvciA9ICJEaWRpZXIgU3RldmVucyAoaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbSkiDQogICAgICAgIGRlc2NyaXB0aW9uID0gIkRldGVjdCBhIFBFIGZpbGUgaW5zaWRlIGEgYnl0ZSBzZXF1ZW5jZSINCiAgICAgICAgbWV0aG9kID0gIkZpbmQgc3RyaW5nIE1aIGZvbGxvd2VkIGJ5IHN0cmluZyBQRSBhdCB0aGUgY29ycmVjdCBvZmZzZXQgKEFkZHJlc3NPZk5ld0V4ZUhlYWRlcikiDQogICAgc3RyaW5nczoNCiAgICAgICAgJGEgPSAiTVoiDQogICAgY29uZGl0aW9uOg0KICAgICAgICBmb3IgYW55IGkgaW4gKDEuLiNhKTogKHVpbnQzMihAYVtpXSArIHVpbnQzMihAYVtpXSArIDB4M0MpKSA9PSAweDAwMDA0NTUwKQ0KfQ0K"

b64e_yara += ":cnVsZSBvZmZpY2Vfb2JmdXNfc3RyaW5ncwp7CiAgc3RyaW5nczoKICAgICRvYmZ1czAgPSAiU3RyUmV2ZXJzZSIKICAgICRvYmZ1czEgPSAibWFlcnRTT0RBIgogICAgJG9iZnVzMiA9ICJlbGlGb1RldmFTIgogICAgJG9iZnVzMyA9ICJ5ZG9CZXNub3BzZXI6IgogICAgJG9iZnVzNCA9ICJQVFRITE1YIgogICAgJG9iZnVzNSA9ICJleGUuIgogICAgJG9iZnVzNiA9ICIvLzpwdHRoIgogICAgJG9iZnVzNyA9ICJsbGVoU2hzVyIKICAgICRvYmZ1czggPSAibGxlaFMudHBpcmNTVyIKICAgICRvZmZpY2UxID0geyBEMCBDRiAxMSBFMCBBMSBCMSAxQSBFMSB9CiAgY29uZGl0aW9uOgogICAgYW55IG9mICgkb2JmdXMqKSBhbmQgYW55IG9mICgkb2ZmaWNlKikKfQogCnJ1bGUgTVpfSGVhZGVyX0luX0RvY3VtZW50CnsKICAgICAgICBtZXRhOgogICAgICAgICAgICAgICAgZGVzY3JpcHRpb24gPSAiTVogSGVhZGVyIGZvdW5kIGluIHRoZSBmaWxlIgogICAgICAgICAgICAgICAgYXV0aG9yID0gIk5hdGhhbiBGb3dsZXIiCiAgICAgICAgICAgICAgICByaXNrID0gImhpZ2giCiAKICAgICAgICBzdHJpbmdzOgogICAgICAgICAgICAgICAgJG16MSA9IHsgNEQgNUEgOTAgMDAgMDMgMDAgMDAgMDAgMDQgfQogICAgICAgICAgICAgICAgJG16MiA9ICI0RDVBOTAwMDAzMDAwMDAwMDQiIG5vY2FzZQogICAgICAgICAgICAgICAgJG16MyA9ICJUaGlzIHByb2dyYW0gY2Fubm90IGJlIHJ1biBpbiAiIG5vY2FzZQogCiAgICAgICAgICAgICAgICAkb2ZmaWNlMSA9IHsgRDAgQ0YgMTEgRTAgQTEgQjEgMUEgRTEgfQogCiAgICAgICAgY29uZGl0aW9uOgogICAgICAgICAgICAgICAgYW55IG9mICgkbXoqKSBhbmQgYW55IG9mICgkb2ZmaWNlKikKfQoKcnVsZSBuZXR3aXJlCnsKICBzdHJpbmdzOgogICAgJHMwID0gIlNNVFAgUGFzc3dvcmQiIGZ1bGx3b3JkIG5vY2FzZSB3aWRlIGFzY2lpCiAgICAkczEgPSAiSFRUUCBTZXJ2ZXIiIGZ1bGx3b3JkIG5vY2FzZSB3aWRlIGFzY2lpCiAgICAkczIgPSAiU01UUCBTZXJ2ZXIiIGZ1bGx3b3JkIG5vY2FzZSB3aWRlIGFzY2lpCiAgICAkczMgPSAiTW96aWxsYSBGaXJlZm94IiBmdWxsd29yZCBub2Nhc2Ugd2lkZSBhc2NpaQogICAgJHM0ID0gIkhUVFAgVXNlciIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzNSA9ICJTTVRQIFVzZXIiIGZ1bGx3b3JkIG5vY2FzZSB3aWRlIGFzY2lpCiAgICAkczYgPSAiSFRUUCBQYXNzd29yZCIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzNyA9ICJVU0VSTkFNRSIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzOCA9ICJtb3pjcnQxOS5kbGwiIGZ1bGx3b3JkIG5vY2FzZSB3aWRlIGFzY2lpCiAgICAkczkgPSAiUE9QMyBVc2VyIiBmdWxsd29yZCBub2Nhc2Ugd2lkZSBhc2NpaQogICAgJHMxMCA9ICJzcWxpdGUzLmRsbCIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzMTEgPSAiQ29tU3BlYyIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzMTIgPSAiMGAuZGF0YSIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzMTMgPSAibG9jYWxob3N0IiBmdWxsd29yZCBub2Nhc2Ugd2lkZSBhc2NpaQogICAgJHMxNCA9ICJuc3MzLmRsbCIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzMTUgPSAiUEsxMVNEUl9EZWNyeXB0IiBmdWxsd29yZCBub2Nhc2Ugd2lkZSBhc2NpaQogICAgJHMxNiA9ICIlc1xcc2lnbm9ucy5zcWxpdGUiIGZ1bGx3b3JkIG5vY2FzZSB3aWRlIGFzY2lpCiAgICAkczE3ID0gInBsYzQuZGxsIiBmdWxsd29yZCBub2Nhc2Ugd2lkZSBhc2NpaQogICAgJHMxOCA9ICJtb3pnbHVlLmRsbCIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRzMTkgPSAiSU1BUCBQYXNzd29yZCIgZnVsbHdvcmQgbm9jYXNlIHdpZGUgYXNjaWkKICAgICRlbnRyeXBvaW50T3BDb2RlID0geyA1NSA4OSA/PyA1NyA1NiA1MyA4MSA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyB9CiAgY29uZGl0aW9uOgogICAgYWxsIG9mIHRoZW0KfQogCnJ1bGUgbmV0d2lyZV9zdHJpbmdzCnsKICBzdHJpbmdzOgogICAgJGNvZGUwID0geyA1NSA4OSA/PyA1NyA1NiA1MyA4MSA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4QiA/PyA/PyA4QiA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MyA4OSA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MiA4OSA/PyBFOCA/PyA/PyA/PyA/PyA4OSA/PyA/PyA4NSA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MiA4OSA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MSA4OSA/PyA/PyA4QiA/PyA4OSA/PyA/PyA/PyA4QiA/PyA4OSA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4MyA/PyA/PyA4OSA/PyA/PyA4MyA/PyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4NSA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4NSA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyA4QiA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MCA1MCBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyAgfQogICAgJGNvZGUxID0geyA1NSA4OSA/PyA1NyA1NiA1MyA4MSA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4NCA/PyA3NSA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4NCA/PyA3NSA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyBFOSA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyAgfQogICAgJGNvZGUyID0geyA1NSA4OSA/PyA1NyA1NiA1MyA4MSA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4QiA/PyA/PyAwRiBCNiA/PyA/PyA4NSA/PyA3RSA/PyA4QiA/PyA/PyAzOSA/PyA/PyA/PyA/PyA/PyA3NSA/PyBBMSA/PyA/PyA/PyA/PyA4NSA/PyA3NCA/PyA4OSA/PyA/PyA/PyA4OSA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4RCA/PyA/PyAzQyA/PyAwRiA4NyA/PyA/PyA/PyA/PyAwRiBCNiA/PyBGRiA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBFOSA/PyA/PyA/PyA/PyA4RCA/PyA/PyA4OSA/PyA/PyA/PyA4OSA/PyA/PyA/PyA4QiA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4NCA/PyAwRiA4NCA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSAgfQogICAgJGNvZGUzID0geyA1NSA4OSA/PyA1MyA4MSA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MSBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MCBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MCA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MCA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA3NyA/PyA4MyA/PyA/PyA3NyA/PyA4MyA/PyA/PyAwRiA4MyA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NSA/PyA/PyA/PyA/PyBFOSA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA3NyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NSA/PyA/PyA/PyA/PyBFOSA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NSA/PyA/PyA/PyA/PyBFOSA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA3NyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyAgfQogICAgJGNvZGU0ID0geyA1NSA4OSA/PyA1NyA1NiA1MyA4MSA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MSA1MSA4OSA/PyA4MyA/PyA/PyA3NSA/PyBFQiA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MiA1MiA4NSA/PyA3NSA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MCBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyBFOSA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyA/PyA/PyA4NSA/PyA3NSA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyBDNyA/PyA/PyAgfQogICAgJGNvZGU1ID0geyA1NSA4OSA/PyA1NyA1NiA1MyA4MSA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4QiA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyA/PyA/PyA0MiA4OSA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4MyA/PyA/PyA4OSA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyAwNSA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MSA4OSA/PyA4NSA/PyAwRiA4NCA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4QiA/PyA4QiA/PyA4OSA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4QiA/PyA/PyA/PyA/PyA/PyAyNSA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA1MiAgfQogICAgJGNvZGU2ID0geyA1NSA4OSA/PyA4MSA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4QiA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NCA/PyA/PyA/PyA/PyA4MyA/PyA/PyAwRiA4NSA/PyA/PyA/PyA/PyA4RCA/PyA/PyA4OSA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4MyA/PyA/PyA4NCA/PyA3NCA/PyBCOCA/PyA/PyA/PyA/PyBFOSA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4NCA/PyAwRiA4NCA/PyA/PyA/PyA/PyBDNyA/PyA/PyA/PyA/PyA/PyA/PyBFOCA/PyA/PyA/PyA/PyA4RCA/PyA/PyA/PyA/PyA/PyA4OSB9CiAgICAkY29kZTcgPSB7IDU1IDg5ID8/IDU2IDUzIDgxID8/ID8/ID8/ID8/ID8/IEM3ID8/ID8/ID8/ID8/ID8/ID8/ID8/IEM3ID8/ID8/ID8/ID8/ID8/ID8/ID8/IDhEID8/ID8/ID8/ID8/ID8/IDg5ID8/ID8/IEU4ID8/ID8/ID8/ID8/IEM3ID8/ID8/ID8/ID8/ID8/ID8/ID8/ID8/ID8/IDg5ID8/ID8/IEU4ID8/ID8/ID8/ID8/IDUxIDg1ID8/IDBGIDk1ID8/IDc0ID8/IEM3ID8/ID8/ID8/ID8/ID8/ID8/IEU4ID8/ID8/ID8/ID8/IEM3ID8/ID8/ID8/ID8/ID8/ID8/ID8/IDg5ID8/ID8/IEU4ID8/ID8/ID8/ID8/IDg1ID8/IDhEID8/ID8/ID8/ID8/ID8/IDc1ID8/IEVCID8/IEM3ID8/ID8/ID8/ID8/ID8/ID8/ID8/ID8/ID8/IDg5ID8/ID8/IEU4ID8/ID8/ID8/ID8/IDUyIDg1ID8/IDc0ID8/IEU5ID8/ID8/ID8/ID8/IDg5ID8/ID8/IEZGID8/IEVCID8/IDg5ID8/ID8/IEU4ID8/ID8/ID8/ID8/IDU2IDg0ID8/IDBGIDg0ID8/ID8/ID8/ID8/IDhCID8/ID8/ID8/ID8/ID8/IDgzID8/ID8/IDc0ID8/IEI4ID8/ID8/ID8/ID8/IDBGIDgyID8/ID8/ID8/ID8/IDgzID8/ID8/IDBGIDg1ID8/ID8/ID8/ID8/IEVCID8/IDgzID8/ID8/ID8/ID8/ID8/ID8/IDBGIH0KICAgICRjb2RlOCA9IHsgNTUgODkgPz8gODEgPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzYgPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gPz8gPz8gOEQgPz8gPz8gODkgPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gOEIgPz8gPz8gODkgPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gRTggPz8gPz8gPz8gPz8gODMgPz8gPz8gODUgPz8gMEYgODUgPz8gPz8gPz8gPz8gRTkgPz8gPz8gPz8gPz8gRkYgPz8gPz8gOEQgPz8gPz8gPz8gPz8gPz8gODkgPz8gPz8gPz8gOEIgPz8gPz8gODkgPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gOEQgPz8gPz8gPz8gPz8gPz8gODkgPz8gPz8gRTggPz8gPz8gPz8gPz8gOEQgPz8gPz8gODkgPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gOEQgPz8gPz8gIH0KICAgICRjb2RlOSA9IHsgNTUgODkgPz8gNTcgNTYgNTMgODEgPz8gPz8gPz8gPz8gPz8gOEQgPz8gPz8gQkUgPz8gPz8gPz8gPz8gQjkgPz8gPz8gPz8gPz8gPz8gQTQgQzcgPz8gPz8gPz8gPz8gPz8gPz8gRTggPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gODkgPz8gPz8gRTggPz8gPz8gPz8gPz8gQTMgPz8gPz8gPz8gPz8gODUgPz8gNzUgPz8gRUIgPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gRTggPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gODkgPz8gPz8gRTggPz8gPz8gPz8gPz8gQTMgPz8gPz8gPz8gPz8gODUgPz8gNzUgPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gPz8gPz8gRTkgPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gOEQgPz8gPz8gODkgPz8gPz8gRTggPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gOEQgPz8gPz8gODkgPz8gPz8gODkgPz8gPz8gRTggPz8gPz8gPz8gPz8gNTIgPz8gODUgPz8gNzUgPz8gRUIgPz8gQzcgPz8gPz8gPz8gPz8gPz8gPz8gPz8gQzcgPz8gPz8gIH0KICBjb25kaXRpb246CiAgICBhbGwgb2YgdGhlbQp9Cg=="

_core(b64e_yara)
# Century College, 2015-2016, e-mail shawn.hughes@century.edu with any questions, thoughts, concerns, bug reports, etc. Feedback is appreciated.
