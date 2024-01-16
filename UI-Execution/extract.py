import re
import openpyxl
from ruamel.yaml import YAML
from openpyxl.drawing.image import Image

RESULT_PATH = "Mihome/Mihome-result/"
YAML_PATH = "./Mihome/Mihome-result/elements.yml"

wb = openpyxl.Workbook()
sheet = wb.active
yaml = YAML(typ='safe')

sheet['A1'] = "Element Name"
sheet['B1'] = "Before Click"
sheet['C1'] = "After Click"
sheet['D1'] = "@name"
sheet['E1'] = "@text"
line = 2
with open(YAML_PATH, encoding="utf-8") as f:
    data = yaml.load(f)
    # print(data['clickedElementsList'])
    for element in data['elementStoreMap']:
        e = data['elementStoreMap'][element]["element"]
        result = (element, data['elementStoreMap'][element]["reqImg"], data['elementStoreMap'][element]["resImg"], e["name"],
                  e["text"])
        sheet[f'A{line}'] = e["xpath"]
        try:
            sheet[f'B{line}'].hyperlink = RESULT_PATH + "/" + result[1][result[1].find('/') + 1:]
        except Exception as ex:
            sheet[f'B{line}'] = result[1]
        try:
            sheet[f'C{line}'].hyperlink = RESULT_PATH + "/" + result[2][result[2].find('/') + 1:]
        except Exception as ex:
            sheet[f'C{line}'] = result[2]
        sheet[f'D{line}'] = e["name"]
        sheet[f'E{line}'] = e["text"]

        line += 1
        # if ("android.widget.CheckBox" in data['elementStoreMap'][element]["className"]):
        #     print(data['elementStoreMap'][element]["url"], data['elementStoreMap'][element]["id"])

wb.save("test.xlsx")
