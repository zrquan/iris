var codeql_advisory_cves_mapped_w_commits = [];
var all_db_names = [];
var all_method_info = [];
var all_cve_tags = {};
var all_cve_to_db_name = {};
var globalSelectedCVEId = "";
var globalDBName = "";

function escapeCode(code) {
  if (code) {
    return code
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  } else {
    return "";
  }
}

function removeAlertLabel(alertId) {
  $(".code-flow-tp-checkbox").each((i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-index"));
    if (elemAlertId == alertId) {
      $(elem).prop("checked", false);
    }
  });
  $(".code-flow-fp-checkbox").each((i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-index"));
    if (elemAlertId == alertId) {
      $(elem).prop("checked", false);
    }
  });
}

function labelAlert(alertId, isTruePos) {
  $(".code-flow-tp-checkbox").each((i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-index"));
    if (elemAlertId == alertId) {
      $(elem).prop("checked", isTruePos);
    }
  });
  $(".code-flow-fp-checkbox").each((i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-index"));
    if (elemAlertId == alertId) {
      $(elem).prop("checked", !isTruePos);
    }
  });
}

function labelSimilarSink(alertId, codeFlowId, isTruePos) {
  let thisCodeFlow = $(`#code-flow-${alertId}-${codeFlowId}`);
  let thisSinkTxt = thisCodeFlow.find(".code-flow-item.last code").text();
  let thisSinkLoc = thisCodeFlow.find(".code-flow-item.last a").attr("href");
  let labelElem = (label) => (i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-index"));
    let elemCodeFlowId = parseInt($(elem).attr("data-code-flow-index"));
    let elemCodeFlow = $(`#code-flow-${elemAlertId}-${elemCodeFlowId}`);
    let elemSinkTxt = elemCodeFlow.find(".code-flow-item.last code").text();
    let elemSinkLoc = elemCodeFlow.find(".code-flow-item.last a").attr("href");
    if (thisSinkTxt == elemSinkTxt && thisSinkLoc == elemSinkLoc) {
      $(elem).prop("checked", label);
    }
  };
  $(".code-flow-tp-checkbox").each(labelElem(isTruePos));
  $(".code-flow-fp-checkbox").each(labelElem(!isTruePos));
}

function labelSimilarSource(alertId, codeFlowId, isTruePos) {
  let thisCodeFlow = $(`#code-flow-${alertId}-${codeFlowId}`);
  let thisSourceTxt = thisCodeFlow.find(".code-flow-item.first code").text();
  let thisSourceLoc = thisCodeFlow.find(".code-flow-item.first a").attr("href");
  let labelElem = (label) => (i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-index"));
    let elemCodeFlowId = parseInt($(elem).attr("data-code-flow-index"));
    let elemCodeFlow = $(`#code-flow-${elemAlertId}-${elemCodeFlowId}`);
    let elemSourceTxt = elemCodeFlow.find(".code-flow-item.first code").text();
    let elemSourceLoc = elemCodeFlow.find(".code-flow-item.first a").attr("href");
    if (thisSourceTxt == elemSourceTxt && thisSourceLoc == elemSourceLoc) {
      $(elem).prop("checked", label);
    }
  };
  $(".code-flow-tp-checkbox").each(labelElem(isTruePos));
  $(".code-flow-fp-checkbox").each(labelElem(!isTruePos));
}

function loadSidebarRowCWEIds(row, db_name, cwe_ids, i, agg, callback) {
  if (i < cwe_ids.length) {
    let curr_cwe_id = cwe_ids[i];
    if (WORKING_CWE_IDS[curr_cwe_id]) {
      $.ajax({
        url: `/codeql/${SIDEBAR_OUTPUT_DIR}/${db_name}/${WORKING_CWE_IDS[curr_cwe_id]}`,
        type: "GET",
        success: (_) => {
          loadSidebarRowCWEIds(row, db_name, cwe_ids, i + 1, agg + `<span class="cwe-id highlight">${curr_cwe_id} ✅</span>`, callback);
        },
        error: (_) => {
          loadSidebarRowCWEIds(row, db_name, cwe_ids, i + 1, agg + `<span class="cwe-id">${curr_cwe_id}</span>`, callback);
        }
      })
    } else {
      loadSidebarRowCWEIds(row, db_name, cwe_ids, i + 1, agg + `<span class="cwe-id">${curr_cwe_id}</span>`, callback);
    }
  } else {
    callback(agg);
  }
}

function loadSidebarRows(row_id, callback) {
  if (row_id < codeql_advisory_cves_mapped_w_commits.length) {
    let row = codeql_advisory_cves_mapped_w_commits[row_id];
    if (!row["commits"] || row["commits"] === "" || row["cwe"] === "" || row["cve"] === "") {
      loadSidebarRows(row_id + 1, callback);
    } else {
      let cve_id = row["cve"];
      if (!all_cve_to_db_name[cve_id]) {
        loadSidebarRows(row_id + 1, callback);
      } else {
        let db_name = all_cve_to_db_name[cve_id];
        let commits = row["commits"].split(";");
        let project = commits[0].split("/")[4];
        let cwe_ids = row["cwe"].split(";");
        if (cwe_ids.some((cwe_id) => WORKING_CWE_IDS[cwe_id])) {
          loadSidebarRowCWEIds(row, db_name, cwe_ids, 0, "", (cwe_ids_html) => {
            let html = `
<li id="project-${row["cve"]}" onclick="clickProject('${row["cve"]}')">
<span class="cve-id">${row["cve"]}</span>
<span class="project">${project}</span>
${cwe_ids_html}
</li>`;
            $("#projects").append(html);
            loadSidebarRows(row_id + 1, callback);
          })
        } else {
          loadSidebarRows(row_id + 1, callback);
        }
      }
    }
  } else {
    callback()
  }
}

function loadCodeQLAdvisoryCVEsMappedWCommits(data) {
  const searchParams = new URLSearchParams(window.location.search);
  if (searchParams.has("cwe")) {
    let cwe_id = searchParams.get("cwe");
    if (cwe_id != "") {
      $("#cwe-filter").val(cwe_id);
      codeql_advisory_cves_mapped_w_commits = data.filter((row) => {
        if (!row["cwe"]) {
          return false;
        } else {
          return row["cwe"].split(";").indexOf(`CWE-${cwe_id}`) >= 0;
        }
      });
    } else {
      codeql_advisory_cves_mapped_w_commits = data;
    }
  } else {
    codeql_advisory_cves_mapped_w_commits = data;
  }

  loadSidebarRows(0, () => {
    if (searchParams.has("cve")) {
      let cve_id = searchParams.get("cve");
      clickProject(cve_id);
    }
  })
}

function downloadObjectAsJson(exportObj, exportName){
  var dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportObj));
  var downloadAnchorNode = document.createElement('a');
  downloadAnchorNode.setAttribute("href", dataStr);
  downloadAnchorNode.setAttribute("download", exportName + ".json");
  document.body.appendChild(downloadAnchorNode); // required for firefox
  downloadAnchorNode.click();
  downloadAnchorNode.remove();
}

function getCurrentManualLabelResult() {
  let resultJson = [];
  $(".code-flow-tp-checkbox").each((i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-index"));
    let elemCodeFlowId = parseInt($(elem).attr("data-code-flow-index"));
    resultJson.push({
      "alert_id": elemAlertId,
      "code_flow_id": elemCodeFlowId,
      "is_true_pos": $(elem).is(":checked"),
      "is_false_pos": $(`#code-flow-fp-checkbox-${elemAlertId}-${elemCodeFlowId}`).is(":checked")
    });
  });
  return resultJson;
}

function saveResult() {
  if (globalDBName == "") {
    alert("No CVE selected");
  } else {
    $.ajax({
      url: "/save-result",
      type: "POST",
      data: {
        "db_name": globalDBName,
        "content": getCurrentManualLabelResult(),
      },
      success: (_) => { alert("Save Success!"); },
      error: (_) => { alert("Save Failed!"); },
    });
  }
}

function downloadResult() {
  if (globalDBName == "") {
    alert("No CVE selected");
  } else {
    let resultJson = getCurrentManualLabelResult();
    downloadObjectAsJson(resultJson, `${globalDBName}`);
  }
}

function getFileNameLineNumFromLoc(loc) {
  let uri = loc["location"]["physicalLocation"]["artifactLocation"]["uri"];
  let lineNum = loc["location"]["physicalLocation"]["region"]["startLine"];
  let baseURIParts = uri.split("/");
  let fileNameWExt = baseURIParts[baseURIParts.length - 1];
  let fileName = fileNameWExt.substring(0, fileNameWExt.indexOf(".java"));
  return `${fileName}:${lineNum}`;
}

function getLocFileLevelLabel(cve_id, loc) {
  let uri = loc["location"]["physicalLocation"]["artifactLocation"]["uri"];
  if (all_method_info[cve_id]) {
    return all_method_info[cve_id]["file_level"].indexOf(uri) >= 0;
  } else {
    return false;
  }
}

function getEnclosingItem(uri, lineNum, itemLocs) {
  let item = null;
  let maxItemStartLine = null;
  for (let i = 0; i < itemLocs.length; i++) {
    let currItemLoc = itemLocs[i];
    let currItemFile = currItemLoc["file"];
    let currItemStartLine = parseInt(currItemLoc["start_line"]);
    let currItemEndLine = parseInt(currItemLoc["end_line"]);
    if (currItemFile == uri && currItemStartLine <= lineNum + 1 && currItemEndLine >= lineNum - 1) {
      if (!item || currItemStartLine > maxItemStartLine) {
        item = currItemLoc["name"];
        maxItemStartLine = currItemStartLine;
      }
    }
  }
  return item;
}

function getLocMethodLevelLabel(cve_id, loc, class_locs, func_locs) {
  if (!all_method_info[cve_id]) {
    return false;
  }

  let uri = loc["location"]["physicalLocation"]["artifactLocation"]["uri"];
  let lineNum = loc["location"]["physicalLocation"]["region"]["startLine"];

  let func = getEnclosingItem(uri, lineNum, func_locs);
  if (!func) { return false; }

  let clazz = getEnclosingItem(uri, lineNum, class_locs);
  if (!clazz) { return false; }

  let location = `${uri}:${clazz}:${func}`;
  return all_method_info[cve_id]["method_level"].indexOf(location) >= 0;
}

function getCodeFlowFileLevelLabel(cve_id, codeFlow) {
  return codeFlow["threadFlows"][0]["locations"].map((loc) => {
    return getLocFileLevelLabel(cve_id, loc);
  });
}

function getCodeFlowMethodLevelLabel(cve_id, codeFlow, class_locs, func_locs) {
  return codeFlow["threadFlows"][0]["locations"].map((loc) => {
    return getLocMethodLevelLabel(cve_id, loc, class_locs, func_locs);
  });
}

function getGithubLocationURL(cveRow, loc) {
  // https://github.com/perwendel/spark/blob/2.5.1/src/main/java/spark/resource/ClassPathResource.java#L51-L55
  let cve_id = cveRow["cve"];
  let repoURL = cveRow["repository_url"];
  let dbNameSplit = globalDBName.split("_");
  let tag = all_cve_tags[cve_id];
  let relativeFileDir = loc["location"]["physicalLocation"]["artifactLocation"]["uri"];
  let lineNum = loc["location"]["physicalLocation"]["region"]["startLine"];
  return `${repoURL}/blob/${tag}/${relativeFileDir}#L${lineNum}`;
}

function loadClassLocations(cve_id, db_name, callback) {
  $.ajax({
    url: `/codeql/outputs/${db_name}/fetch_class_locs.ql/results.csv`,
    type: "GET",
    success: (csv_content) => {
      let parsed_result = Papa.parse(csv_content, { header: true });
      let data = parsed_result.data;
      callback(data)
    }
  })
}

function loadFuncLocations(cve_id, db_name, callback) {
  $.ajax({
    url: `/codeql/outputs/${db_name}/fetch_func_locs.ql/results.csv`,
    type: "GET",
    success: (csv_content) => {
      let parsed_result = Papa.parse(csv_content, { header: true });
      let data = parsed_result.data;
      callback(data)
    }
  })
}

function queryNVDDescription(cve_id, callback) {
  $.ajax({
    url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve_id}`,
    type: "GET",
    dataType: "json",
    success: (data) => {
      if (data["vulnerabilities"].length > 0) {
        let vul = data["vulnerabilities"][0];
        let descriptions = vul["cve"]["descriptions"]
          .filter((desc) => desc["lang"] == "en")
          .map((desc) => `<p>${desc["value"]}</p>`).join("");
        callback(descriptions);
      } else {
        callback("<p>Vulnerability not found in NVD database</p>")
      }
    },
  })
}

function loadOutputSarif(output_dir, db_name, query, callback) {
  $.ajax({
    url: `/codeql/${output_dir}/${db_name}/${query}/results.sarif`,
    type: "GET",
    dataType: "json",
    success: (data) => {
      callback(data)
    }
  })
}

function loadManualLabel(cve_id, db_name, callback) {
  $.ajax({
    url: `/codeql/saikat-outputs/${db_name}/manual/results.json`,
    type: "GET",
    dataType: "json",
    success: (data) => callback(data),
    error: (_) => {
      $.ajax({
        url: `/codeql/outputs/${db_name}/manual/results.json`,
        type: "GET",
        dataType: "json",
        success: (data) => callback(data),
        error: (_) => callback(null),
      });
    }
  })
}

function loadAllDBNames(callback) {
  $.ajax({
    url: `/codeql/${OUTPUT_DIR}/`, // CHANGE THIS!
    type: "GET",
    success: (data) => {
      const regexp = /<a href="(\S+)\/">/g;
      const results = [...data.matchAll(regexp)].map((d) => d[1]);
      all_db_names = results;
      callback();
    },
  });
}

function loadCVEGithubTag(callback) {
  $.ajax({
    url: "/all_project_tags.csv",
    type: "GET",
    success: (csv_content) => {
      let parsed_result = Papa.parse(csv_content, { header: true });
      all_cve_tags = {};
      all_cve_to_db_name = {};
      for (let i = 0; i < parsed_result.data.length; i++) {
        let row = parsed_result.data[i];
        all_cve_tags[row["cve"]] = row["tag"];
        all_cve_to_db_name[row["cve"]] = row["project"];
      }
      callback();
    },
  });
}

function loadAllMethodInfo(callback) {
  $.ajax({
    url: "/all_method_info_saikat.csv",
    type: "GET",
    success: (csv_content) => {
      let parsed_result = Papa.parse(csv_content, { header: true });
      all_method_info = {}
      for (let i = 0; i < parsed_result.data.length; i++) {
        let row = parsed_result.data[i];
        if (!all_method_info[row["cve"]]) {
          all_method_info[row["cve"]] = {
            "file_level": [],
            "method_level": [],
            "locations": [],
          }
        }

        let fileLevelLocation = `${row["file"]}`
        all_method_info[row["cve"]]["file_level"].push(fileLevelLocation);

        let methodLevelLocation = `${row["file"]}:${row["class"]}:${row["method"]}`
        all_method_info[row["cve"]]["method_level"].push(methodLevelLocation);

        all_method_info[row["cve"]]["locations"].push({
          "commit": row["commit"],
          "file": row["file"],
          "class": row["class"],
          "method": row["method"],
        });
      }
      callback()
    },
  });
}

function loadAdvisoryCVEs() {
  $.ajax({
    url: "/codeql/codeql_advisory_cves_mapped_w_commits.csv",
    type: "GET",
    success: (csv_content) => {
      let parsed_result = Papa.parse(csv_content, { header: true });
      let data = parsed_result.data;
      loadCodeQLAdvisoryCVEsMappedWCommits(data);
    },
  });
}
