#!/usr/bin/python2

# This script created by Shawn Hughes for the automated triage and/or analysis of potential malware samples. 2015-2016.

# Currently the script utilizes "swftools", "python-magic", "yara", and "oletools". Please ensure that these programs and/or modules are installed prior to execution.
# pip install oletools
# apt-get install swftools
# apt-get install python-magic
# pip install yara

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

def _hardcode_setup():
    # A user may want to hardcode in and out paths for their analysis files. If no config file exists, it will ask if you want to store your in/out options in one and use them from then on out.
    sane = 0
    home_dir = str(os.path.expanduser('~'))
    input_conf = raw_input('-- : --  Please enter full path to input sample directory: ')
    output_conf = raw_input('-- : --  Please enter full path to sample/analysis output directory: ')
    if not os.path.exists(input_conf) or not os.path.exists(output_conf):
        sys.exit("-- : --  Invalid paths detected. Please check input. Run again to re-enter paths.")
    print '-- : --  Is this input directory correct "'+str(input_conf)+'"?'
    print '-- : --  Is this output directory correct "'+str(output_conf)+'"?'
    while sane == 0:
        dir_choice = raw_input('-- : --  Yes or No: ')
        if dir_choice == 'Yes':
            conf_file = open(home_dir+'/automal_conf.conf', 'w')
            conf_file.write('ipath='+str(input_conf)+'\n')
            conf_file.write('opath='+str(output_conf)+'\n')
            conf_file.close()
            sane = 1
        if dir_choice == 'No':
            sys.exit('-- : --  Exited on incorrect paths. Run again to re-enter.')
        if dir_choice != 'No' and dir_choice != 'Yes':
            print '-- : --  Invalid choice, try again. Yes or No.'
            pass

def _get_hc_dirs():
    try:
        read_conf = open(str(os.path.expanduser('~'))+'/automal_conf.conf', 'r').readlines()
    except IOError:
        sys.exit("-- : --  Unable to access conf. file. Run and re-enter new conf. file paths.")
    for line in read_conf:
	    if line.startswith('ipath'):
		    input_path = str(line.split('=')[1]).strip()
	    if line.startswith('opath'):
		    output_path = str(line.split('=')[1]).strip()
    return(input_path, output_path)

def _setup(b64e_yara):
    # Take user input, generate list containing samples to be processed, provide other running information on input and output, etc.

    # We also create a dir. in /tmp for use with random command output/extraction/etc.
    if len(sys.argv) == 3:
        orig_path = sys.argv[1]
        orig_target_list = os.listdir(orig_path)
        if len(sys.argv) > 2:
            out_path = str(sys.argv[2])
            if out_path.endswith("/"):
                out_path = out_path[0:-1]
    else:
        # Here we either directly take user input for a one time directory use, or for re-writing hardcoded directory conf. file, or using pre-existing conf. file defined directories.
        chk_sane = 0
        while chk_sane == 0:
            if os.path.exists(str(os.path.expanduser('~'))):
                chk_hc = raw_input('-- : --  Conf. file detected.\n-- : --  Would you like to create and use a new one?\n-- : --  Yes or No: ')
            else:
                chk_hc = raw_input('-- : --  Would you like to hardcode a config file for all future input and output directory requests?\n-- : --  Yes or No: ')
            if chk_hc == 'Yes':
                _hardcode_setup()
	        out_path = _get_hc_dirs()[1]
	        if out_path.endswith('/'):
	    	    out_path = out_path[0:-1]
	        orig_path = _get_hc_dirs()[0]
	        if orig_path.endswith('/'):
		    orig_path = orig_path[0:-1]
                orig_target_list = os.listdir(str(orig_path))
                chk_sane = 1
            if chk_hc == 'No':
                if os.path.exists(str(os.path.expanduser('~')+'/automal_conf.conf')):
                    print "-- : --  Conf. file detected and being used, grabbing paths..."
                    out_path = _get_hc_dirs()[1]
                    if out_path.endswith('/'):
                        out_path = out_path[0:-1]
                    orig_path = _get_hc_dirs()[0]
                    if orig_path.endswith('/'):
                        orig_path = orig_path[0:-1]
                    orig_target_list = os.listdir(str(orig_path))
                    chk_sane = 1
                else:
                    try:
                        print "-- : --  One time directory entry chosen."
                        print "-- : --  Please enter full path to directory containing malware samples."
                        orig_path = raw_input("-- : --  Path: ")
                        orig_target_list = os.listdir(str(orig_path))
                        print "-- : --  Please enter full path to directory for auto_mal.py results to be saved to."
                        out_path = raw_input("-- : --  Path: ")
                        if out_path.endswith("/"):
                            out_path = out_path[0:-1]
                        chk_sane = 1
                    except OSError:
                        sys.exit("-- : --  Input not accepted, please run again and specify proper input and output directories.")

            if chk_hc != 'Yes' and chk_hc != 'No':
                print '-- : --  Invalid choice, try again. Yes or No.'
                pass
    
    # Create target list.
    full_targ_list = []
    for targ in orig_target_list:
         full_targ_list.append(orig_path+"/"+targ)
    
    # QA
    if not os.path.exists('/tmp/automal'):
        os.makedirs('/tmp/automal')
    


    # This script urilizes two yara rules as part of it's "analysis", we need to decode the hardcoded yara rules and save them out to the tmp directory.
    b64e_data_maldoc = b64e_yara.split(':')[0]
    b64e_data_pe = b64e_yara.split(':')[1]

    b64d_maldoc =  base64.b64decode(b64e_data_maldoc)
    b64d_data_pe = base64.b64decode(b64e_data_pe)

    if not os.path.exists('/tmp/automal/contains_pe_file.yara'):
        yara_file1 = open('/tmp/automal/contains_pe_file.yara', 'w')
        yara_file1.write(b64d_data_pe)
        yara_file1.close()

    if not os.path.exists('/tmp/automal/maldoc.yara'):
        yara_file2 = open('/tmp/automal/maldoc.yara', 'w')
        yara_file2.write(b64d_maldoc)
        yara_file2.close()

    return(orig_path, orig_target_list, full_targ_list, out_path)

def _get_file_type(full_targ_path):
    # This function takes the full path of a target sample and determines/returns the file type via python-magic.
    try:
        magicObj = magic.open(magic.MAGIC_NONE)
        magicObj.load()
        magic_out = str(magicObj.file(full_targ_path))
    except AttributeError:
        magic_out = str(magic.from_file(full_targ_path))

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
                swf_ioc_res = "Present"

    if len(swf_ioc_res) == 0:
        swf_ioc_res = "None"

    extract_list_fns = []
    for out in command2_list:
        if "JPEG" in out:
            j_id = out.rfind(' ')+1
            j_id = int(out[j_id:len(out)])
            # Sometimes picture extraction doesn't occur... correctly, so we suppress the output. If we get it, great, if we don't whatever, for now.
            os_null = open(os.devnull, 'wb')
            subprocess.Popen(['swfextract', full_targ_path, '-j', str(j_id), '-o', '/tmp/automal/'+str(j_id)+'.jpg'], stdout=os_null, stderr=os_null)
            subprocess.Popen(['swfextract', full_targ_path, '-p', str(j_id), '-o', '/tmp/automal/'+str(j_id)+'.png'], stdout=os_null, stderr=os_null)
            extract_list_fns.append('/tmp/automal/'+str(j_id))
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
    contains_pe_file_rule = yara.compile(filepath='/tmp/automal/contains_pe_file.yara')
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

    maldoc_file_rule = yara.compile(filepath='/tmp/automal/maldoc.yara')
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

    return(yara_pe_res, yara_maldoc_res)

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
    if not os.path.exists(automal_dir+'/Master_Output_Table.csv'):
        master_out = open(automal_dir+'/Master_Output_Table.csv', 'a')
        master_out.write('File Name, MD5 Hash, File Type, OLE-VB Macro Present, Yara Signature Hit, IOC Present,\n')
    else:
        master_out = open(automal_dir+'/Master_Output_Table.csv', 'a')

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

        if "Macromedia Flash" in f_type:
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

            master_out.write(str(targ[targ.rfind('/')+1:len(targ)])+','+str(out_file_info[2])+',SWF,NA,'+str(yara_maldoc_res)+':'+str(yara_pe_res)+','+str(swf_res[3])+',\n')
            out_file_info[0].close()

# ---------------------------------------------
# -------------------- OLE --------------------
# ---------------------------------------------

        if "Microsoft Word" in f_type or "Composite Document" in f_type or "Microsoft Excel" in f_type:
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

            master_out.write(str(targ[targ.rfind('/')+1:len(targ)])+','+str(out_file_info[2])+',OLE,'+str(ole_res[0])+','+str(yara_maldoc_res)+':'+str(yara_pe_res)+','+str(ole_res[3])+',\n')
            out_file_info[0].close()
        
        subprocess.Popen(['mv', targ, mv_path], stdout=os_null, stderr=os_null)
        sample_counter += 1

    print "-- : -- Processed "+str(sample_counter)+" total samples."
    print "-- : -- Finished."
    master_out.close()

b64e_yara = "LyoNCiAgVmVyc2lvbiAwLjAuMiAyMDE0LzEyLzE2DQogIFNvdXJjZSBjb2RlIHB1dCBpbiBwdWJsaWMgZG9tYWluIGJ5IERpZGllciBTdGV2ZW5zLCBubyBDb3B5cmlnaHQNCiAgaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbQ0KICBVc2UgYXQgeW91ciBvd24gcmlzaw0KDQogIFRoZXNlIGFyZSBZQVJBIHJ1bGVzIHRvIGRldGVjdCBzaGVsbGNvZGUsIHRyYW5zbGF0ZWQgZnJvbSBYT1JTZWFyY2gncyB3aWxkY2FyZCBydWxlcywNCiAgd2hpY2ggdGhlbXNlbHZlcyB3ZXJlIGRldmVsb3BlZCBiYXNlZCBvbiBGcmFuayBCb2xkZXdpbidzIHNoZWxsY29kZSBkZXRlY3RvciB1c2VkIGluIE9mZmljZU1hbFNjYW5uZXIuDQoNCiAgU2hvcnRjb21pbmdzLCBvciB0b2RvJ3MgOy0pIDoNCiAgICBSZW1haW5pbmcgWE9SU2VhcmNoIHdpbGRjYXJkIHJ1bGVzOg0KICAgICAgR2V0RUlQIG1ldGhvZCAyOjEwOkVCKEo7MSlFOChKOzQpKEI7MDEwMTE/Pz8pDQogICAgICBHZXRFSVAgbWV0aG9kIDM6MTA6RTkoSjs0KUU4KEo7NCkoQjswMTAxMT8/PykNCg0KICBIaXN0b3J5Og0KICAgIDIwMTQvMTIvMTU6IHN0YXJ0DQogICAgMjAxNC8xMi8xNjogZXh0cmEgZG9jdW1lbnRhdGlvbg0KKi8NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEFQSSBIYXNoaW5nOjEwOkFDODRDMDc0MDdDMUNGMEQwMUM3RUJGNDgxRkYNCiAgICBBUEkgSGFzaGluZyBiaXM6MTA6QUM4NEMwNzQwN0MxQ0YwNzAxQzdFQkY0ODFGRg0KKi8NCnJ1bGUgbWFsZG9jX0FQSV9oYXNoaW5nDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7QUMgODQgQzAgNzQgMDcgQzEgQ0YgMEQgMDEgQzcgRUIgRjQgODEgRkZ9DQogICAgICAgICRhMiA9IHtBQyA4NCBDMCA3NCAwNyBDMSBDRiAwNyAwMSBDNyBFQiBGNCA4MSBGRn0NCiAgICBjb25kaXRpb246DQogICAgICAgIGFueSBvZiB0aGVtDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBGdW5jdGlvbiBwcm9sb2cgc2lnbmF0dXJlOjEwOjU1OEJFQzgzQzQNCiAgICBGdW5jdGlvbiBwcm9sb2cgc2lnbmF0dXJlOjEwOjU1OEJFQzgxRUMNCiAgICBGdW5jdGlvbiBwcm9sb2cgc2lnbmF0dXJlOjEwOjU1OEJFQ0VCDQogICAgRnVuY3Rpb24gcHJvbG9nIHNpZ25hdHVyZToxMDo1NThCRUNFOA0KICAgIEZ1bmN0aW9uIHByb2xvZyBzaWduYXR1cmU6MTA6NTU4QkVDRTkNCiovDQpydWxlIG1hbGRvY19mdW5jdGlvbl9wcm9sb2dfc2lnbmF0dXJlDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7NTUgOEIgRUMgODEgRUN9DQogICAgICAgICRhMiA9IHs1NSA4QiBFQyA4MyBDNH0NCiAgICAgICAgJGEzID0gezU1IDhCIEVDIEU4fQ0KICAgICAgICAkYTQgPSB7NTUgOEIgRUMgRTl9DQogICAgICAgICRhNSA9IHs1NSA4QiBFQyBFQn0NCiAgICBjb25kaXRpb246DQogICAgICAgIGFueSBvZiB0aGVtDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBTdHJ1Y3R1cmVkIGV4Y2VwdGlvbiBoYW5kbGluZyA6MTA6NjQ4QihCOzAwPz8/MTAxKTAwMDAwMDAwDQogICAgU3RydWN0dXJlZCBleGNlcHRpb24gaGFuZGxpbmcgYmlzOjEwOjY0QTEwMDAwMDAwMA0KKi8NCnJ1bGUgbWFsZG9jX3N0cnVjdHVyZWRfZXhjZXB0aW9uX2hhbmRsaW5nDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7NjQgOEIgKDA1fDBEfDE1fDFEfDI1fDJEfDM1fDNEKSAwMCAwMCAwMCAwMH0NCiAgICAgICAgJGEyID0gezY0IEExIDAwIDAwIDAwIDAwfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgYW55IG9mIHRoZW0NCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEluZGlyZWN0IGZ1bmN0aW9uIGNhbGw6MTA6RkY3NShCO0E/Pz8/Pz8/KUZGNTUoQjtBPz8/Pz8/PykNCiovDQpydWxlIG1hbGRvY19pbmRpcmVjdF9mdW5jdGlvbl9jYWxsXzENCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhID0ge0ZGIDc1ID8/IEZGIDU1ID8/fQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgZm9yIGFueSBpIGluICgxLi4jYSk6ICh1aW50OChAYVtpXSArIDIpID09IHVpbnQ4KEBhW2ldICsgNSkpDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBJbmRpcmVjdCBmdW5jdGlvbiBjYWxsIGJpczoxMDpGRkI1KEI7QT8/Pz8/Pz8pKEI7Qj8/Pz8/Pz8pKEI7Qz8/Pz8/Pz8pKEI7RD8/Pz8/Pz8pRkY5NShCO0E/Pz8/Pz8/KShCO0I/Pz8/Pz8/KShCO0M/Pz8/Pz8/KShCO0Q/Pz8/Pz8/KQ0KKi8NCnJ1bGUgbWFsZG9jX2luZGlyZWN0X2Z1bmN0aW9uX2NhbGxfMg0Kew0KICAgIG1ldGE6DQogICAgICAgIGF1dGhvciA9ICJEaWRpZXIgU3RldmVucyAoaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbSkiDQogICAgc3RyaW5nczoNCiAgICAgICAgJGEgPSB7RkYgQjUgPz8gPz8gPz8gPz8gRkYgOTUgPz8gPz8gPz8gPz99DQogICAgY29uZGl0aW9uOg0KICAgICAgICBmb3IgYW55IGkgaW4gKDEuLiNhKTogKCh1aW50OChAYVtpXSArIDIpID09IHVpbnQ4KEBhW2ldICsgOCkpIGFuZCAodWludDgoQGFbaV0gKyAzKSA9PSB1aW50OChAYVtpXSArIDkpKSBhbmQgKHVpbnQ4KEBhW2ldICsgNCkgPT0gdWludDgoQGFbaV0gKyAxMCkpIGFuZCAodWludDgoQGFbaV0gKyA1KSA9PSB1aW50OChAYVtpXSArIDExKSkpDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBJbmRpcmVjdCBmdW5jdGlvbiBjYWxsIHRyaXM6MTA6RkZCNyhCOz8/Pz8/Pz8/KShCOz8/Pz8/Pz8/KShCOz8/Pz8/Pz8/KShCOz8/Pz8/Pz8/KUZGNTcoQjs/Pz8/Pz8/PykNCiovDQpydWxlIG1hbGRvY19pbmRpcmVjdF9mdW5jdGlvbl9jYWxsXzMNCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhID0ge0ZGIEI3ID8/ID8/ID8/ID8/IEZGIDU3ID8/fQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgJGENCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEZpbmQga2VybmVsMzIgYmFzZSBtZXRob2QgMToxMDo2NDhCKEI7MDA/Pz8xMDEpMzAwMDAwMDANCiAgICBGaW5kIGtlcm5lbDMyIGJhc2UgbWV0aG9kIDFiaXM6MTA6NjRBMTMwMDAwMDAwDQoqLw0KcnVsZSBtYWxkb2NfZmluZF9rZXJuZWwzMl9iYXNlX21ldGhvZF8xDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYTEgPSB7NjQgOEIgKDA1fDBEfDE1fDFEfDI1fDJEfDM1fDNEKSAzMCAwMCAwMCAwMH0NCiAgICAgICAgJGEyID0gezY0IEExIDMwIDAwIDAwIDAwfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgYW55IG9mIHRoZW0NCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEZpbmQga2VybmVsMzIgYmFzZSBtZXRob2QgMjoxMDozMShCOzExQT8/QT8/KShCOzEwMTAwQT8/KTMwNjQ4QihCOzAwQj8/QT8/KQ0KKi8NCnJ1bGUgbWFsZG9jX2ZpbmRfa2VybmVsMzJfYmFzZV9tZXRob2RfMg0Kew0KICAgIG1ldGE6DQogICAgICAgIGF1dGhvciA9ICJEaWRpZXIgU3RldmVucyAoaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbSkiDQogICAgc3RyaW5nczoNCiAgICAgICAgJGEgPSB7MzEgPz8gPz8gMzAgNjQgOEIgPz99DQogICAgY29uZGl0aW9uOg0KICAgICAgICBmb3IgYW55IGkgaW4gKDEuLiNhKTogKCh1aW50OChAYVtpXSArIDEpID49IDB4QzApIGFuZCAoKCh1aW50OChAYVtpXSArIDEpICYgMHgzOCkgPj4gMykgPT0gKHVpbnQ4KEBhW2ldICsgMSkgJiAweDA3KSkgYW5kICgodWludDgoQGFbaV0gKyAyKSAmIDB4RjgpID09IDB4QTApIGFuZCAodWludDgoQGFbaV0gKyA2KSA8PSAweDNGKSBhbmQgKCgodWludDgoQGFbaV0gKyA2KSAmIDB4MzgpID4+IDMpICE9ICh1aW50OChAYVtpXSArIDYpICYgMHgwNykpKQ0KfQ0KDQovKg0KWE9SU2VhcmNoIHdpbGRjYXJkIHJ1bGUocyk6DQogICAgRmluZCBrZXJuZWwzMiBiYXNlIG1ldGhvZCAzOjEwOjY4MzAwMDAwMDAoQjswMTAxMUE/Pyk2NDhCKEI7MDBCPz9BPz8pDQoqLw0KcnVsZSBtYWxkb2NfZmluZF9rZXJuZWwzMl9iYXNlX21ldGhvZF8zDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYSA9IHs2OCAzMCAwMCAwMCAwMCAoNTh8NTl8NUF8NUJ8NUN8NUR8NUV8NUYpIDY0IDhCID8/fQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgZm9yIGFueSBpIGluICgxLi4jYSk6ICgoKHVpbnQ4KEBhW2ldICsgNSkgJiAweDA3KSA9PSAodWludDgoQGFbaV0gKyA4KSAmIDB4MDcpKSBhbmQgKHVpbnQ4KEBhW2ldICsgOCkgPD0gMHgzRikgYW5kICgoKHVpbnQ4KEBhW2ldICsgOCkgJiAweDM4KSA+PiAzKSAhPSAodWludDgoQGFbaV0gKyA4KSAmIDB4MDcpKSkNCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEdldEVJUCBtZXRob2QgMToxMDpFODAwMDAwMDAwKEI7MDEwMTE/Pz8pDQoqLw0KcnVsZSBtYWxkb2NfZ2V0RUlQX21ldGhvZF8xDQp7DQogICAgbWV0YToNCiAgICAgICAgYXV0aG9yID0gIkRpZGllciBTdGV2ZW5zIChodHRwczovL0RpZGllclN0ZXZlbnMuY29tKSINCiAgICBzdHJpbmdzOg0KICAgICAgICAkYSA9IHtFOCAwMCAwMCAwMCAwMCAoNTh8NTl8NUF8NUJ8NUN8NUR8NUV8NUYpfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgJGENCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIEdldEVJUCBtZXRob2QgNCBGTERaL0ZTVEVOViBbZXNwLTEyXToxMDpEOUVFRDk3NDI0RjQoQjswMTAxMT8/PykNCiAgICBHZXRFSVAgbWV0aG9kIDQ6MTA6RDlFRTlCRDk3NDI0RjQoQjswMTAxMT8/PykNCiovDQpydWxlIG1hbGRvY19nZXRFSVBfbWV0aG9kXzQNCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhMSA9IHtEOSBFRSBEOSA3NCAyNCBGNCAoNTh8NTl8NUF8NUJ8NUN8NUR8NUV8NUYpfQ0KICAgICAgICAkYTIgPSB7RDkgRUUgOUIgRDkgNzQgMjQgRjQgKDU4fDU5fDVBfDVCfDVDfDVEfDVFfDVGKX0NCiAgICBjb25kaXRpb246DQogICAgICAgIGFueSBvZiB0aGVtDQp9DQoNCi8qDQpYT1JTZWFyY2ggd2lsZGNhcmQgcnVsZShzKToNCiAgICBPTEUgZmlsZSBtYWdpYyBudW1iZXI6MTA6RDBDRjExRTANCiovDQpydWxlIG1hbGRvY19PTEVfZmlsZV9tYWdpY19udW1iZXINCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhID0ge0QwIENGIDExIEUwfQ0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgJGENCn0NCg0KLyoNClhPUlNlYXJjaCB3aWxkY2FyZCBydWxlKHMpOg0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1VcmxEb3dubG9hZFRvRmlsZQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1HZXRUZW1wUGF0aA0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1HZXRXaW5kb3dzRGlyZWN0b3J5DQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPUdldFN5c3RlbURpcmVjdG9yeQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1XaW5FeGVjDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPVNoZWxsRXhlY3V0ZQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1Jc0JhZFJlYWRQdHINCiAgICBTdXNwaWNpb3VzIHN0cmluZ3M6MjpzdHI9SXNCYWRXcml0ZVB0cg0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1DcmVhdGVGaWxlDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPUNsb3NlSGFuZGxlDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPVJlYWRGaWxlDQogICAgU3VzcGljaW91cyBzdHJpbmdzOjI6c3RyPVdyaXRlRmlsZQ0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1TZXRGaWxlUG9pbnRlcg0KICAgIFN1c3BpY2lvdXMgc3RyaW5nczoyOnN0cj1WaXJ0dWFsQWxsb2MNCiAgICBTdXNwaWNpb3VzIHN0cmluZ3M6MjpzdHI9R2V0UHJvY0FkZHINCiAgICBTdXNwaWNpb3VzIHN0cmluZ3M6MjpzdHI9TG9hZExpYnJhcnkNCiovDQpydWxlIG1hbGRvY19zdXNwaWNpb3VzX3N0cmluZ3MNCnsNCiAgICBtZXRhOg0KICAgICAgICBhdXRob3IgPSAiRGlkaWVyIFN0ZXZlbnMgKGh0dHBzOi8vRGlkaWVyU3RldmVucy5jb20pIg0KICAgIHN0cmluZ3M6DQogICAgICAgICRhMDEgPSAiQ2xvc2VIYW5kbGUiDQogICAgICAgICRhMDIgPSAiQ3JlYXRlRmlsZSINCiAgICAgICAgJGEwMyA9ICJHZXRQcm9jQWRkciINCiAgICAgICAgJGEwNCA9ICJHZXRTeXN0ZW1EaXJlY3RvcnkiDQogICAgICAgICRhMDUgPSAiR2V0VGVtcFBhdGgiDQogICAgICAgICRhMDYgPSAiR2V0V2luZG93c0RpcmVjdG9yeSINCiAgICAgICAgJGEwNyA9ICJJc0JhZFJlYWRQdHIiDQogICAgICAgICRhMDggPSAiSXNCYWRXcml0ZVB0ciINCiAgICAgICAgJGEwOSA9ICJMb2FkTGlicmFyeSINCiAgICAgICAgJGExMCA9ICJSZWFkRmlsZSINCiAgICAgICAgJGExMSA9ICJTZXRGaWxlUG9pbnRlciINCiAgICAgICAgJGExMiA9ICJTaGVsbEV4ZWN1dGUiDQogICAgICAgICRhMTMgPSAiVXJsRG93bmxvYWRUb0ZpbGUiDQogICAgICAgICRhMTQgPSAiVmlydHVhbEFsbG9jIg0KICAgICAgICAkYTE1ID0gIldpbkV4ZWMiDQogICAgICAgICRhMTYgPSAiV3JpdGVGaWxlIg0KICAgIGNvbmRpdGlvbjoNCiAgICAgICAgYW55IG9mIHRoZW0NCn0NCg=="
b64e_yara += ":LyoNCiAgVmVyc2lvbiAwLjAuMSAyMDE0LzEyLzEzDQogIFNvdXJjZSBjb2RlIHB1dCBpbiBwdWJsaWMgZG9tYWluIGJ5IERpZGllciBTdGV2ZW5zLCBubyBDb3B5cmlnaHQNCiAgaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbQ0KICBVc2UgYXQgeW91ciBvd24gcmlzaw0KDQogIFNob3J0Y29taW5ncywgb3IgdG9kbydzIDstKSA6DQoNCiAgSGlzdG9yeToNCiAgICAyMDE0LzEyLzEzOiBzdGFydA0KICAgIDIwMTQvMTIvMTU6IGRvY3VtZW50YXRpb24NCiovDQoNCnJ1bGUgQ29udGFpbnNfUEVfRmlsZQ0Kew0KICAgIG1ldGE6DQogICAgICAgIGF1dGhvciA9ICJEaWRpZXIgU3RldmVucyAoaHR0cHM6Ly9EaWRpZXJTdGV2ZW5zLmNvbSkiDQogICAgICAgIGRlc2NyaXB0aW9uID0gIkRldGVjdCBhIFBFIGZpbGUgaW5zaWRlIGEgYnl0ZSBzZXF1ZW5jZSINCiAgICAgICAgbWV0aG9kID0gIkZpbmQgc3RyaW5nIE1aIGZvbGxvd2VkIGJ5IHN0cmluZyBQRSBhdCB0aGUgY29ycmVjdCBvZmZzZXQgKEFkZHJlc3NPZk5ld0V4ZUhlYWRlcikiDQogICAgc3RyaW5nczoNCiAgICAgICAgJGEgPSAiTVoiDQogICAgY29uZGl0aW9uOg0KICAgICAgICBmb3IgYW55IGkgaW4gKDEuLiNhKTogKHVpbnQzMihAYVtpXSArIHVpbnQzMihAYVtpXSArIDB4M0MpKSA9PSAweDAwMDA0NTUwKQ0KfQ0K"

_core(b64e_yara)
# Century College, 2015-2016, e-mail shawn.hughes@century.edu with any questions, thoughts, concerns, bug reports, etc. Feedback is appreciated.
