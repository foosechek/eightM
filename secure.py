import os
import sys
import re
from subprocess import call

csfTemplate="""[Header]
   Version = 4.3
   Hash Algorithm = sha256
   Engine = CAAM
   Engine Configuration = 0
   Certificate Format = X509
   Signature Format = CMS
 
[Install SRK]
   File = "SRK_LIST"
   Source index = 0
 
[Install CSFK]
   File = "CSF_PEM"
 
[Authenticate CSF]
 
[Install Key]
   Verification index = 0
   Target index = 2
   File = "KEY_PEM"
 
[Authenticate Data]
   Verification index = 2
"""

# secure scipt
# execute make and capture output
# extract hab data (print_fit_hab equiv)

###############################################################################
# printFitHab : python equivalent to shell script in processor dir.
###############################################################################
def printFitHab(usrArgs):
    
    BL32="tee.bin"
    SEEK_OFFSET = 0x8400   # seek for image write to boot media + 33KB
    MYSTERY_OFFSET = 0x3000 # no clue
    UBOOT_LOAD_ADDR = 0x40200000 # look this up
    ATF_LOAD_ADDR = 0x910000  # start of OCRAM?
    TEE_LOAD_ADDR = 0xFE000000  # look this up

    printFitHabArgs = usrArgs["PRINT_FIT_HAB_ARGS"].split(" ")
    fit_offset=int(printFitHabArgs[0],16)
    
    imageComponent =[]     # list of dictionaries for components
    
# U-boot component    
    uboot_sign_offset=(fit_offset - SEEK_OFFSET + MYSTERY_OFFSET)
    try:
        uboot_stat = os.stat("u-boot-nodtb.bin")
        uboot_size = uboot_stat.st_size
        uboot_load_addr = UBOOT_LOAD_ADDR
        uboot = {'name': "uboot"}
        uboot.update({'size': uboot_size})
        uboot.update({'addr': uboot_load_addr})
        uboot.update({'offs': uboot_sign_offset})
        imageComponent.append(uboot)
    except:
        print("u-boot-nodtb.bin file missing");
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               # Arm Trusted Firmware (ATF) component
# BL31 component
    try:
        atf_stat = os.stat("bl31.bin")
        atf_size = atf_stat.st_size
        atf_sign_offset = (uboot_sign_offset + uboot_size)
        atf_load_addr = ATF_LOAD_ADDR
        atf = {'name':'atf'}
        atf.update({'addr': atf_load_addr})
        atf.update({'size': atf_size})
        atf.update({'offs': atf_sign_offset})
        imageComponent.append(atf)
    except:
        print("bl31.bin  ARM trusted firmware file missing")
   
# Trusted Execution Environment (TEE) component (optional)
    try:
        tee_sign_offset = (atf_sign_offset + atf_size)
        tee_load_addr = TEE_LOAD_ADDR
        tee_stat = os.stat(BL32)
        tee_size  = tee_stat.st_size
     
        tee = {'name':'tee'}
        tee.update({'addr': tee_load_addr})
        tee.update({'size': tee_size})
        tee.update({'offs': tee_sign_offset})
        imageComponent.append(tee)
    except:
        tee_size = 0
        print("no tee file")
    
# Device Tree Binary (DTB) component(s)
    last_sign_offset=(tee_sign_offset + tee_size)
    last_size=tee_size
    last_load_addr=uboot_load_addr + uboot_size

# there can be more than one.
    for i in range(1,len(printFitHabArgs)):
        fdt_stat = os.stat(printFitHabArgs[i])
        fdt_size = fdt_stat.st_size
        fdt_sign_offset = last_sign_offset
        fdt_load_addr =  last_load_addr
        fdt = {'name':'fdt'+str(i-1)}
        fdt.update({'addr': fdt_load_addr})
        fdt.update({'size': fdt_size})
        fdt.update({'offs': fdt_sign_offset})
        imageComponent.append(fdt)                
        last_size = fdt_size
        
        last_size_offset = last_sign_offset + last_size
        last_load_addr = last_load_addr + last_size

    return(imageComponent)

###############################################################################
# make call : execute the mkimage_imx8 and record a log file.
#           : parse the make.log to extract necessary component params.
###############################################################################
def makeFlashBin():
    # call to make the flash.bin file - Refer to makefile for constituents
    os.system("make SOC=iMX8M flash_evk > make.log 2>&1")
    
    imageComponent = []
    # parse output file for content 
    f_makeLog = open('make.log','r')
    for line in f_makeLog:
        if re.search("sld hab block", line):
            items = line.split()
            sld = {'name':'sld_hab'}
            sld.update({'addr':int(items[3],0)})
            sld.update({'offs':int(items[4],0)})
            sld.update({'size':int(items[5],0)})
            imageComponent.append(sld)
            
        if re.search("spl hab block", line):
            items = line.split()
            spl = {'name':'spl_hab'}
            spl.update({'addr':int(items[3],0)})
            spl.update({'offs':int(items[4],0)})
            spl.update({'size':int(items[5],0)})
            imageComponent.append(spl)

        if re.search(" csf_off", line):
            items = line.split()
            spl = {'name':'csf_off'}
            spl.update({'offs':int(items[1],0)})
            imageComponent.append(spl)

        if re.search("sld_csf_off", line):
            items = line.split()
            sld = {'name':'sld_csf_off'}
            sld.update({'offs':int(items[1],0)})
            imageComponent.append(sld)

    return(imageComponent)

###############################################################################
# generateCFG : this creates the csf files from the gathered components
###############################################################################
def generateCSF(mkimageList, FitHabList,usrArgs):

    # copy CSF template for each desired output
    splCsf = csfTemplate
    fitCsf = csfTemplate

    srkList = usrArgs["CST_DIR"]+"crts/"+usrArgs["SRK_LIST"]
    csfPem = usrArgs["CST_DIR"]+"crts/"+usrArgs["CSF_PEM"]
    keyPem = usrArgs["CST_DIR"]+"crts/"+usrArgs["KEY_PEM"]
    
    splCsf= splCsf.replace("SRK_LIST",srkList)
    splCsf= splCsf.replace("CSF_PEM",csfPem)
    splCsf= splCsf.replace("KEY_PEM",keyPem)

    fitCsf= fitCsf.replace("SRK_LIST",srkList)
    fitCsf= fitCsf.replace("CSF_PEM",csfPem)
    fitCsf= fitCsf.replace("KEY_PEM",keyPem)

# find the slp_hab entry in the mkimageList and populate the Block args
    for i, item in enumerate(mkimageList):
        if(item["name"]=="spl_hab"):
            splIndex=i

    append =  "   Blocks ="
    append += " 0x"+ '{:08x}'.format(mkimageList[splIndex]["addr"],'02X')
    append += " 0x"+ '{:08x}'.format(mkimageList[splIndex]["offs"],'02X')
    append += " 0x"+ '{:08x}'.format(mkimageList[splIndex]["size"],'02X')
    append += ' "flash.bin"'
    splCsf += append
# write the spl file out
    f_splCsf = open("spl.csf",'w')
    f_splCsf.write(splCsf)
    f_splCsf.close()

# find the elements and populate the block args
    index = 0
    for i in FitHabList:
        index+=1
        if index == 1:
            append = "   Blocks ="
        else:
            append = "           "
        append += " 0x"+ '{:08x}'.format(i["addr"],'02X')
        append += " 0x"+ '{:08x}'.format(i["offs"],'02X')
        append += " 0x"+ '{:08x}'.format(i["size"],'02X')
        append += ' "flash.bin", \\\n'
        fitCsf += append
    # find the sld_hab entry in the mkimageList and populate the last block args
    for i, item in enumerate(mkimageList):
        if(item["name"]=="sld_hab"):
            sldIndex=i
    append = "           "
    append += " 0x"+ '{:08x}'.format(mkimageList[sldIndex]["addr"],'02X')
    append += " 0x"+ '{:08x}'.format(mkimageList[sldIndex]["offs"],'02X')
    append += " 0x"+ '{:08x}'.format(mkimageList[sldIndex]["size"],'02X')
    append += ' "flash.bin"'
    fitCsf += append
# write the fit file out
    f_fitCsf = open("fit.csf",'w')
    f_fitCsf.write(fitCsf)
    f_fitCsf.close()

# execute the code signing tool for each csf, merge output file.

    cstExec = usrArgs["CST_DIR"]+"linux"+usrArgs["CST_WIDTH"]+"/bin/cst"
    os.system(cstExec + " --o spl_csf.bin --i spl.csf")
    os.system(cstExec + " --o fit_csf.bin --i fit.csf")
    os.system("cp flash.bin signed_flash.bin")
    # find the sld_hab entry in the mkimageList and populate the Blocks args
    for i, item in enumerate(mkimageList):
        if(item["name"]=="csf_off"):
            break
    os.system("dd if=spl_csf.bin of=signed_flash.bin seek="+str(mkimageList[i]['offs'])+" bs=1 conv=notrunc")

    for i, item in enumerate(mkimageList):
        if(item["name"]=="sld_csf_off"):
            break
    os.system("dd if=fit_csf.bin of=signed_flash.bin seek="+str(mkimageList[i]['offs'])+" bs=1 conv=notrunc")


###############################################################################
#  fillCstArgs : read config file and populate the usrArgs list
###############################################################################
def fillUsrArgs():
    f_config = open("../secure.cfg","r")

    usrArgs = {}

    for line in f_config:
        if re.search("#", line):
            continue
        else:
            line=line.rstrip()
            items = line.split("=")
            usrArgs.update({items[0]:items[1]})

    return(usrArgs)

###############################################################################
# this portion is not complete, just moved the prints from the earlier sections.
###############################################################################
def printReport():
    for i in mkimageList:
        print("0x"+ '{:08x}'.format(i["addr"],'02X'), end=' ')
        print("0x"+ '{:08x}'.format(i["offs"],'02X'), end=' ')
        print("0x"+ '{:08x}'.format(i["size"],'02X'), end= '\n')

    for i in FitHabList:
        print("0x"+ '{:08x}'.format(i["addr"],'02X'), end=' ')
        print("0x"+ '{:08x}'.format(i["offs"],'02X'), end=' ')
        print("0x"+ '{:08x}'.format(i["size"],'02X'), end= '\n')

    print("Blocks =", end=' ')
    print("0x"+ '{:08x}'.format(uboot_load_addr,'02X'), end=' ')
    print("0x"+ '{:08x}'.format(uboot_sign_offset,'02X'), end=' ')
    print("0x"+ '{:08x}'.format(uboot_size,'02X'), end= ' ')
    print('"flash.bin", \\')

    print("\t\t", end='')
    print("0x"+ '{:08x}'.format(atf_load_addr,'02X'), end=' ')
    print("0x"+ '{:08x}'.format(atf_sign_offset,'02X'), end=' ')
    print("0x"+ '{:08x}'.format(atf_size,'02X'), end= ' ')
    print('"flash.bin", \\')

    if tee_size != 0:
        print("\t\t", end='')
        print("0x"+ '{:08x}'.format(tee_load_addr,'02X'), end=' ')
        print("0x"+ '{:08x}'.format(tee_sign_offset,'02X'), end=' ')
        print("0x"+ '{:08x}'.format(tee_size,'02X'), end= ' ')
        print('"flash.bin", \\')

        print("\t\t", end='')
        print("0x"+ '{:08x}'.format(fdt_load_addr,'02X'), end=' ')
        print("0x"+ '{:08x}'.format(fdt_sign_offset,'02X'), end=' ')
        print("0x"+ '{:08x}'.format(fdt_size,'02X'), end= ' ')
        if i==len(sys.argv)-1:
            print('"flash.bin"')
        else:
            print('"flash.bin", \\')

        
# MAIN          
mkimageList = makeFlashBin()
os.chdir("iMX8M")
usrArgs = fillUsrArgs()
FitHabList = printFitHab(usrArgs)
generateCSF(mkimageList, FitHabList,usrArgs)






