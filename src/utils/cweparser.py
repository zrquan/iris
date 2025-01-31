

def get_cwe_mappings():
    cwefile=f"cwec_v4.12.xml"

    import xml.etree.ElementTree as ET
    import re
    tree = ET.parse(cwefile)
    root = tree.getroot()

    natures=dict()
    namemap=dict()
    for element in root[0]: 

        for child in element:       
            if "Related_Weakness" in child.tag:
                for w in child:
                    if "Related_Weakness" in w.tag:
                        natures[w.attrib['Nature']] = natures.get(w.attrib['Nature'], 0) + 1
                        if w.attrib['Nature'] == 'ChildOf':
                            print(";".join([element.attrib['ID'], element.attrib['Name'], w.attrib['Nature'], w.attrib['CWE_ID']]))

def is_parent(parent, child, df):
    if parent == child:
        return True
    children = df[df['parentid'] == parent]['childid'].tolist()
    if len(children) == 0:
        return False
    for c in children:
        if is_parent(c, child, df):
            return True
    return False


def check_cwe(true_id, predicted_id):
    import pandas as pd
    true_id = int(true_id)
    predicted_id = int(predicted_id)    
    df = pd.read_csv("cwemappings.csv", delimiter=";")
    if true_id == predicted_id:
        return True
    else: 
        return is_parent(predicted_id, true_id, df)

if __name__ == '__main__':
    import sys
    print(check_cwe(sys.argv[1], sys.argv[2]))

