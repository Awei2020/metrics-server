# -*- coding: utf-8 -*-
# 加载scan_results.json文件
import json
#判断文件是否在当前目录下
import os
#获取当前目录
path = os.getcwd()
#获取当前目录下的文件
files = os.listdir(path)
#判断文件是否在当前目录下
uri = ""
if 'go.mod'  in files:
    uri = "go.mod"
elif 'package.json' in files:
    uri = "package.json"
elif 'pom.xml' in files:
    uri = "pom.xml"
elif 'requirements.txt' in files:
    uri = "requirements.txt"
elif 'composer.json' in files:
    uri =  "composer.json"
elif 'Gemfile' in files:
    uri = "Gemfile"
elif 'build.gradle' in files:
    uri = "build.gradle"
elif 'build.sbt' in files:
    uri = "build.sbt"
elif 'Cargo.toml' in files:
    uri = "Cargo.toml"
elif 'mix.exs' in files:
    uri = "mix.exs"
elif 'Gopkg.lock' in files:
    uri = "Gopkg.lock"
elif 'go.sum' in files:
    uri = "go.sum"
elif 'yarn.lock' in files:
    uri = "yarn.lock"
elif 'composer.lock' in files:
    uri = "composer.lock"
elif 'Gemfile.lock' in files:
    uri = "Gemfile.lock"
elif 'requirements.lock' in files:
    uri = "requirements.lock"
elif 'pom.lock' in files:
    uri = "pom.lock"
elif 'mix.lock' in files:
    uri = "mix.lock"
elif 'Cargo.lock' in files:
    uri = "Cargo.lock"
elif 'build.lock' in files:
    uri = "build.lock"
elif 'builds.lock' in files:
    uri = "builds.lock"

results = []
with open('scan_results.json', 'r', encoding="utf_8") as f:
    murphy_date = json.load(f)
sarif = {}
#向safi添加数据
sarif["$schema"] = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
sarif["version"] = "2.1.0"
sarif["runs"] = []
sarif["runs"].append({})
sarif["runs"][0]["tool"] = {}
sarif["runs"][0]["tool"]["driver"] = {}
sarif["runs"][0]["tool"]["driver"]["name"] = "Murphy-cli"
sarif["runs"][0]["tool"]["driver"]["rules"] = []
#遍历murphy_date的rules
for i in murphy_date["comps"]:
    if i["vulns"] == []:
        #如果vulns为空，跳过
        continue
    data = {}
    data["id"] = "murphysec-" + i["vulns"][0]["cve_id"]
    data["shortDescription"] = {}
    data["shortDescription"]["text"] = i["vulns"][0]["level"]+ "  severity - " + i["comp_name"] + '@' + i["comp_version"]
    data["fullDescription"] = {}
    data["fullDescription"]["text"] = i["vulns"][0]["level"] + "  severity - " + i["comp_name"] + '@' + i["comp_version"]
    data["help"] = {}
    data["help"]["text"] = ""

    data["help"]["text"] = '* ' + str(i["vulns"][0]["description"])
    sarif["runs"][0]["tool"]["driver"]["rules"].append(data)
    res = {}
    res["ruleId"] = "murphysec-" + i["vulns"][0]["cve_id"]
    res["level"] = "warning"
    res["message"] = {}
    res["message"]["text"] = i["vulns"][0]["level"] + i["comp_name"] + i["comp_version"]
    res["locations"] = []
    locations = {}
    locations["physicalLocation"] = {}
    locations["physicalLocation"]["artifactLocation"] = {}
    locations["physicalLocation"]["artifactLocation"]["uri"] = uri
    locations["physicalLocation"]["region"] = {}
    locations["physicalLocation"]["region"]["startLine"] = 1
    res["locations"].append(locations)
    results.append(res)

sarif["runs"][0]["results"] = results
#将sarif写入文件
with open('results.sarif', 'w', encoding="utf_8") as f:
    json.dump(sarif, f, indent=4, separators=(',', ': '))


print(sarif)





