const QUERY_NAMES = {
  "cwe-022wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-22",
  },
  "cwe-022wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-22 (CodeQL)",
  },
  "cwe-078wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-78",
  },
  "cwe-078wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-78 (CodeQL)",
  },
  "cwe-079wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-79",
  },
  "cwe-079wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-79 (CodeQL)",
  },
  "cwe-094wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-94",
  },
  "cwe-094wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-94 (CodeQL)",
  },
}

function download() {
  let project = getQueriedProjectFromURL();
  if (project) {
    let resultJson = getCurrentManualLabelResult();
    let trial = $(".cwe-query-tab.active").attr("data-run-id");
    let query = $(".cwe-query-tab.active").attr("data-query");
    downloadObjectAsJson(resultJson, `${project}__${trial}__${query}.json`);
  } else {
    alert("No project selected");
  }
}

function save() {

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
  let labels = [];
  $(".code-flow-tp-checkbox").each((i, elem) => {
    let elemAlertId = parseInt($(elem).attr("data-alert-id"));
    let elemCodeFlowId = parseInt($(elem).attr("data-code-flow-id"));
    labels.push({
      "alert_id": elemAlertId,
      "code_flow_id": elemCodeFlowId,
      "is_true_pos": $(elem).is(":checked"),
      "is_false_pos": $(`#code-flow-fp-checkbox-${elemAlertId}-${elemCodeFlowId}`).is(":checked")
    });
  });
  return {
    "project": $("#project-copy").attr("aria-data"),
    "trial": $(".cwe-query-tab.active").attr("data-run-id"),
    "query": $(".cwe-query-tab.active").attr("data-query"),
    "labels": labels,
  };
}

/**
 * Get the URL search parameter `project`
 * @returns string | null
 */
function getQueriedProjectFromURL() {
  const searchParams = new URLSearchParams(window.location.search);
  if (searchParams.has("project")) {
    return searchParams.get("project");
  } else {
    return null;
  }
}

/**
 * Get the URL search parameter `tab`
 * @returns string | null
 */
function getQueriedTabFromURL() {
  const searchParams = new URLSearchParams(window.location.search);
  if (searchParams.has("tab")) {
    return searchParams.get("tab");
  } else {
    return null;
  }
}

function generateHrefURL(project, tab) {
  const searchParams = new URLSearchParams(window.location.search);
  let queryParams = [];
  if (project != null) {
    if (project != "") {
      queryParams.push(`project=${project}`);
    }
  } else if (searchParams.has("project")) {
    queryParams.push(`project=${searchParams.get("project")}`)
  }
  if (tab != null && tab != "") {
    queryParams.push(`tab=${tab}`);
  }
  if (queryParams.length > 0) {
    return VIEWER_HTML_DIR + "?" + queryParams.join("&");
  } else {
    return VIEWER_HTML_DIR;
  }
}

function getScrollParent(node) {
  const regex = /(auto|scroll)/;
  const parents = (_node, ps) => {
    if (_node.parentNode === null) { return ps; }
    return parents(_node.parentNode, ps.concat([_node]));
  };
  const style = (_node, prop) => getComputedStyle(_node, null).getPropertyValue(prop);
  const overflow = _node => style(_node, 'overflow') + style(_node, 'overflow-y') + style(_node, 'overflow-x');
  const scroll = _node => regex.test(overflow(_node));
  const scrollParent = (_node) => {
    if (!(_node instanceof HTMLElement || _node instanceof SVGElement)) {
      return;
    }
    const ps = parents(_node.parentNode, []);
    for (let i = 0; i < ps.length; i += 1) {
      if (scroll(ps[i])) {
        return ps[i];
      }
    }
    return document.scrollingElement || document.documentElement;
  };
  return scrollParent(node);
};

function expandExpandableText(elem, length) {
  let fullText = $(elem).children(".full").text();
  let showLess = `<a href="#" onclick="shrinkExpandableText(this, ${length})" style="text-decoration: none"><br />(Show less)<span class="full" hidden="hidden">${fullText}</span></a>`;
  let parent = $(elem).parent();
  parent.html(fullText + showLess);
}

function shrinkExpandableText(elem, length) {
  let fullText = $(elem).children(".full").text();
  let parent = $(elem).parent();
  let top = parent.offset().top;
  parent.html(expandableTextToHTML(fullText, length));
  $(getScrollParent(parent[0])).animate({ scrollTop: top }, 50);
}

function expandableTextToHTML(text, length) {
  if (text.length > length) {
    let showMore = `... <a href="#" onclick="expandExpandableText(this, ${length})" style="text-decoration: none">(Show more)<span class="full" hidden="hidden">${text}</span></a>`;
    return text.substring(0, length).trim() + showMore;
  } else {
    return text;
  }
}

function renderCWEBadge(cweId) {
  return `<span class="badge text-bg-secondary" style="margin-left: 3px">${cweId}</span>`
}

function checkHasOutput(project, callback) {
  $.ajax({
    url: `${OUTPUT_DIR}/${project}`,
    type: "GET",
    success: () => callback(true),
    error: () => callback(false),
  })
}

function renderSidebarItem(projectRow, index) {
  let queriedProject = getQueriedProjectFromURL();
  let project = projectRow["project"];
  let [author, package] = project.split("_latest")[0].split("__");
  let active = project == queriedProject ? "active" : "";
  checkHasOutput(project, (has) => {
    let badge = has ? `<small><span class="badge text-bg-secondary" style="margin-left: 3px">Has Result</span></small>` : "";
    $(`#sidebar-item-${project} .body`).append(badge);
  });
  return `
    <a id="sidebar-item-${project}" href="${generateHrefURL(project)}" class="list-group-item list-group-item-action ${active} py-3 lh-tight" aria-current="true">
      <div class="body d-flex w-100 align-items-center justify-content-between">
        <span class="mb-1"> <strong class="mb-1">${author}</strong> / ${package}</span>
      </div>
    </a>
  `;
}

function renderSidebar(projects) {
  fold(projects.filter((_) => {
    return true;
  }), [], (projectRow, index, _, callback) => {
    $("#sidebar-cwe-list").append(renderSidebarItem(projectRow, index));
    callback([]);
    // , (html) => {
    //   $("#sidebar-cwe-list").append(html);
    //   callback([]);
    // });
  }, (_) => {
    let project = getQueriedProjectFromURL();
    if (project != null && $(`#sidebar-item-${project}`)[0]) {
      $("#sidebar-cwe-list").animate({
        scrollTop: $(`#sidebar-item-${project}`).offset().top - $("#sidebar-header").outerHeight()
      }, 50);
    }
  });
}

function queryNVDDescription(cveId, callback) {
  fetchJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, (data) => {
    if (data && data["vulnerabilities"].length > 0) {
      let vul = data["vulnerabilities"][0];
      let descriptions = vul["cve"]["descriptions"]
        .filter((desc) => desc["lang"] == "en")
        .map((desc) => `${desc["value"]}`).join("<br />");
      callback(descriptions);
    } else {
      callback("Vulnerability not found in NVD database")
    }
  })
}

function renderCommit(commitLink) {
  let commitParts = commitLink.split("/");
  let commitId = commitParts[commitParts.length - 1].substring(0, 12);
  return `
    <a target="_blank" href="${commitLink}" style="text-decoration: none;">
      <span class="badge text-bg-primary" style="margin-left: 3px">${commitId}</span>
    </a>
  `;
}

function folderToElemId(folder) {
  return `${folder["run_id"]}-${folder["query"]}`;
}

function renderChildFolderTab(folder) {
  let folderElemId = folderToElemId(folder);
  let queryName = QUERY_NAMES[folder["query"]]["display_name"];
  let href = generateHrefURL(null, folderElemId);
  let active = getQueriedTabFromURL() == folderElemId ? "active" : "";
  return `
    <li class="nav-item" role="presentation">
      <a class="nav-link ${active}" href="${href}" id="${folderElemId}-tab">${folder["run_id"]} / ${queryName}</a>
    </li>
  `;
}

function renderTabs(childFolders) {
  let childFolderTabs = childFolders.map(renderChildFolderTab);
  $("#result-tabs").html(childFolderTabs.join(""));
}

function renderCWEQueryTabContent(folder) {
  let folderElemId = folderToElemId(folder);
  return `
    <div class="tab-pane fade cwe-query-tab" id="${folderElemId}" role="tabpanel" aria-labelledby="${folderElemId}-tab">
      <h6><strong>Alarms (<span id="${folderElemId}-num-alerts"></span>)</strong></h6>
      <div id="${folderElemId}-alerts"></div>
    </div>
  `;
}

function renderBasicTabContent(folder) {
  switch (QUERY_NAMES[folder["query"]]["type"]) {
    case "cwe-query": return renderCWEQueryTabContent(folder);
    default: return "";
  }
}

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

function getGithubRawURLFromCodeFlowStep(projectRow, step) {
  // https://raw.githubusercontent.com/perwendel/spark/2.5.1/src/main/java/spark/resource/ClassPathResource.java
  let repoURL = projectRow["git_url"].substring(0, projectRow["git_url"].length - 4).replace("https://github.com/", "https://raw.githubusercontent.com/");
  let tag = projectRow["commit_id"];
  let relativeFileDir = step["location"]["physicalLocation"]["artifactLocation"]["uri"];
  return `${repoURL}/${tag}/${relativeFileDir}`;
}

function getGithubLocationURLFromCodeFlowStep(projectRow, step) {
  // https://github.com/perwendel/spark/blob/2.5.1/src/main/java/spark/resource/ClassPathResource.java#L51-L55
  let repoURL = projectRow["git_url"].substring(0, projectRow["git_url"].length - 4);
  let tag = projectRow["commit_id"];
  let relativeFileDir = step["location"]["physicalLocation"]["artifactLocation"]["uri"];
  let lineNum = step["location"]["physicalLocation"]["region"]["startLine"];
  return `${repoURL}/blob/${tag}/${relativeFileDir}#L${lineNum}`;
}

function resultSarifCodeFlowStepToHTML(stepId, step, projectRow) {
  let locMessage = escapeCode(step["location"]["message"]["text"]);
  let githubLink = getGithubLocationURLFromCodeFlowStep(projectRow, step)
  return `
    <a href="${githubLink}" target="_blank" class="list-group-item list-group-item-action rounded code-flow-item" style="position: inherit!important;">
      <code>${locMessage}</code>
    </a>
  `;
}

function clampText(txt, length) {
  if (txt.length > length) {
    return txt.substring(0, length) + "...";
  } else {
    return txt;
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

function resultSarifCodeFlowToHTML(folder, alarmId, codeFlowId, codeFlow, projectRow) {
  let folderElemId = folderToElemId(folder);

  let steps = codeFlow["threadFlows"][0]["locations"];
  let sourceUrl = getGithubLocationURLFromCodeFlowStep(projectRow, steps[0]);
  let sourceFile = clampText(sourceUrl.split("/").pop().split(".java")[0], 20);
  let sinkUrl = getGithubLocationURLFromCodeFlowStep(projectRow, steps[steps.length - 1]);
  let sinkFile = clampText(sinkUrl.split("/").pop().split(".java")[0], 20);

  let numIntermediateSteps = steps.length;
  let intermediateStepsHTML = steps.map((step, stepId) => {
    return resultSarifCodeFlowStepToHTML(stepId, step, projectRow);
  }).join("");

  let tpRadioId = `${folderElemId}-code-flow-${alarmId}-${codeFlowId}-tp-radio`;
  let fpRadioId = `${folderElemId}-code-flow-${alarmId}-${codeFlowId}-fp-radio`;

  return `
    <div class="code-flow bg-white p-3 border rounded" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}">
      <div class="d-flex pb-2 border-bottom">
        <div class="mt-1 col">
          <strong>
            <i class="fa-regular fa-bookmark"></i> Code Flow #<span>${codeFlowId + 1}</span>
          </strong>
        </div>
        <div class="mt-1 d-flex">
          <div class="me-2">
            <input class="code-flow-tp-checkbox form-check-input me-1" data-alert-id="${alarmId}" data-code-flow-id="${codeFlowId}" type="checkbox" value="" id="${tpRadioId}">
            <label class="form-check-label" for="${tpRadioId}">
              <span class="text-success">True Pos</span>
            </label>
          </div>
          <div>
            <input class="code-flow-fp-checkbox form-check-input me-1" type="checkbox" value="" id="${fpRadioId}">
            <label class="form-check-label" for="${fpRadioId}">
              <span class="text-danger">False Pos</span>
            </label>
          </div>
        </div>
      </div>
      <div class="p-2 mt-2">
        <div class="d-flex mb-1 justify-content-between align-items-start">
          <strong>Source</strong>
          <a target="_blank" href="${sourceUrl}" class="badge rounded-pill text-bg-primary" style="text-decoration: none">${sourceFile}</a>
        </div>
        <pre class="p-2 border rounded bg-body-tertiary overflow-x" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-source-snippet"></pre>
        <div class="d-flex mb-1 justify-content-between align-items-start">
          <strong>Sink</strong>
          <a target="_blank" href="${sinkUrl}" class="badge rounded-pill text-bg-primary" style="text-decoration: none">${sinkFile}</a>
        </div>
        <pre class="p-2 border rounded bg-body-tertiary overflow-x" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-sink-snippet"></pre>
      </div>
      <div id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca" hidden="hidden">
        <div class="d-flex pb-2 border-bottom">
          <strong><i class="fa-regular fa-lightbulb"></i> Contextual Analysis:</strong>
        </div>
        <div class="p-2">
          <p>
            <strong>LLM Judgement: </strong>
            <span id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-judgement"></span>
          </p>
          <p>
            <strong>LLM Explanation: </strong>
            <span id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-explanation"></span>
          </p>
          <p><strong>Prompt: </strong></p>
          <pre class="p-2 border rounded bg-body-tertiary overflow-x" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-prompt"></pre>
        </div>
      </div>
      <div>
        <div class="d-flex pb-2 border-bottom">
          <strong><i class="fa fa-road-barrier"></i> Intermediate Steps (<span>${numIntermediateSteps}</span>):</strong>
        </div>
        <div class="list-group list-group-flush p-2">
          ${intermediateStepsHTML}
        </div>
      </div>
    </div>
  `;
}

function resultSarifAlarmToHTML(folder, alarmId, alarm, projectRow, hideIfNotTP) {
  let folderElemId = folderToElemId(folder);

  let numCodeFlows = 0;
  let codeFlowsHtml = "";
  if (!alarm["codeFlows"]) {
    numCodeFlows = 0;
  } else {
    numCodeFlows = alarm["codeFlows"].length;
    codeFlowsHtml = alarm["codeFlows"].map((codeFlow, codeFlowId) => {
      return resultSarifCodeFlowToHTML(folder, alarmId, codeFlowId, codeFlow, projectRow);
    }).join("");
  }

  let collapseId = `${folderElemId}-alarm-${alarmId}-collapse`;

  return `
    <div class="highlight-toolbar mt-3 ps-3 pe-3 py-1 border rounded bg-body-tertiary" id="${folderElemId}-alarm-${alarmId}">
      <div class="d-flex w-100 align-items-center justify-content-between">
        <a class="mt-3 mb-3" data-bs-toggle="collapse" href="#${collapseId}" style="text-decoration: none" role="button" aria-expanded="true" aria-controls="${collapseId}">
          <strong><i class="fa fa-bell"></i> Alarm #${alarmId + 1} (#Code Flows: ${numCodeFlows})</strong>
        </a>
        <div class="btn-group btn-group-sm" role="group" aria-label="Small button group">
          <button type="button" class="btn btn-outline-primary">Remove Label</button>
          <button type="button" class="btn btn-outline-danger">Label as FP</button>
          <button type="button" class="btn btn-outline-success">Label as TP</button>
        </div>
      </div>
      <div class="collapse show" id="${collapseId}">
        <div class="code-flows d-flex pb-3 border-top pt-3">
          ${codeFlowsHtml}
        </div>
      </div>
    </div>
  `;
}

const LIMIT = 200;

function resultSarifAlarmsToHTML(folder, alarms, projectRow) {
  return alarms.map((alarm, i) => {
    return resultSarifAlarmToHTML(folder, i, alarm, projectRow, i > LIMIT)
  }).join("");
}

function renderResultSarif(folder, resultSarif, projectRow) {
  fetchClassLocations(projectRow["project"], folder["run_id"], (classLocs) => {
    fetchFuncLocations(projectRow["project"], folder["run_id"], (funcLocs) => {
      let folderElemId = folderToElemId(folder);
      let results = resultSarif["runs"][0]["results"];

      // Load main results
      $(`#${folderElemId}-num-alerts`).text(results.length);
      $(`#${folderElemId}-alerts`).html(resultSarifAlarmsToHTML(folder, results, projectRow));

      // Load Source/Sink Snippets from Github
      loadSourceSinkSnippets(folder, resultSarif, projectRow);

      // Load posthoc-filtering result
      loadContextualAnalysisResult(folder, resultSarif, projectRow);
    })
  })
}

class ToCollectFiles {
  constructor(projectRow) {
    this.projectRow = projectRow;
    this.files = {};
  }

  addStep(step, alarmId, codeFlowId, kind) {
    let url = getGithubRawURLFromCodeFlowStep(this.projectRow, step);
    if (!this.files[url]) {
      this.files[url] = []
    }
    this.files[url].push({
      "alarm_id": alarmId,
      "code_flow_id": codeFlowId,
      "kind": kind,
      "line": step["location"]["physicalLocation"]["region"]["startLine"],
    });
  }
}

function loadSourceSinkSnippets(folder, resultSarif, projectRow) {
  let folderElemId = folderToElemId(folder);
  let toCollectFiles = new ToCollectFiles(projectRow);

  for (let alarmId in resultSarif["runs"][0]["results"]) {
    let alarm = resultSarif["runs"][0]["results"][alarmId];
    if (alarm["codeFlows"]) {
      for (let codeFlowId in alarm["codeFlows"]) {
        let codeFlow = alarm["codeFlows"][codeFlowId];
        let codeFlowSteps = codeFlow["threadFlows"][0]["locations"];
        toCollectFiles.addStep(codeFlowSteps[0], alarmId, codeFlowId, "source");
        toCollectFiles.addStep(codeFlowSteps[codeFlowSteps.length - 1], alarmId, codeFlowId, "sink");
      }
    }
  }

  Object.entries(toCollectFiles.files).map(([file, targets]) => {
    fetchFile(file, (fileContent) => {
      if (fileContent) {
        let fileContentLines = fileContent.split("\n");
        for (let targetId in targets) {
          let target = targets[targetId];
          let lineStr = fileContentLines[target["line"] - 1].trim();
          $(`#${folderElemId}-code-flow-${target["alarm_id"]}-${target["code_flow_id"]}-${target["kind"]}-snippet`).text(lineStr);
        }
      }
    })
  })
}

const IS_VUL = `<span class="text-success"><i class="fa-regular fa-circle-check"></i> Is vulnerable</span>`;
const NOT_VUL = `<span class="text-danger"><i class="fa-regular fa-circle-xmark"></i> Not vulnerable</span>`;
const IS_CACHED = `<span class="text-secondary">&nbsp;(Cached)</span>`;

function loadContextualAnalysisResult(folder, resultSarif, projectRow) {
  let folderElemId = folderToElemId(folder);
  let dbName = projectRow["project"];
  let { "run_id": runId, query } = folder;
  fetchJSON(`${OUTPUT_DIR}/${dbName}/${runId}/${query}-posthoc-filter/results.json`, (contextualAnalysis) => {
    if (contextualAnalysis) {
      for (let i in contextualAnalysis) {
        let codeFlowResult = contextualAnalysis[i];

        // Get basic information
        let alarmId = codeFlowResult["result_id"];
        let codeFlowId = codeFlowResult["code_flow_id"];
        let isVul = codeFlowResult["entry"]["result"]["is_vulnerable"];
        let isCached = codeFlowResult["entry"]["using_cache"] ? IS_CACHED : "";
        let explanation = codeFlowResult["entry"]["result"]["explanation"];
        let prompt = codeFlowResult["entry"]["prompt"];

        // Render information onto screen
        $(`#${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca`).removeAttr("hidden");
        $(`#${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-judgement`).html((isVul ? IS_VUL : NOT_VUL) + isCached);
        $(`#${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-explanation`).html(expandableTextToHTML(explanation, 200));
        $(`#${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-prompt`).html(expandableTextToHTML(prompt, 400));

        // Render the quick-access labels
        if (isVul) {
          $(`#${folderElemId}-alarm-${alarmId}-qa-button`).removeAttr("hidden");
          $(`#${folderElemId}-alarm-${alarmId}-qa-button .llm-label`).removeAttr("hidden");
        }
      }
    }
  })
}

function loadTabContent(projectRow, folder) {
  let dbName = projectRow["project"];
  fetchJSON(`${OUTPUT_DIR}/${dbName}/${folder["run_id"]}/${folder["query"]}/results.sarif`, (resultSarif) => {
    if (resultSarif) {
      renderResultSarif(folder, resultSarif, projectRow);
    }
  })
}

function renderBasicTabContents(projectRow, childFolders) {
  // First render the basic tab content
  $("#result-tab-contents").html(childFolders.map(renderBasicTabContent).join(""));
}

function loadResults(projectRow) {
  let dbName = projectRow["project"];

  // Load the directories
  fetchOutputDirectory(dbName, (childFolders) => {
    if (childFolders.length == 0) {
      $("#result-tab-contents").html("<strong>No Result</strong>");
      return;
    }

    // First load the tabs
    renderTabs(childFolders);
    renderBasicTabContents(projectRow, childFolders);

    // Check which tab to load
    let tab = getQueriedTabFromURL();
    let matchFolder = childFolders[0];
    if (tab) {
      matchFolder = childFolders.find((childFolder) => folderToElemId(childFolder) == tab);
    }

    // Load the tab
    loadTabContent(projectRow, matchFolder);
    let folderElemId = folderToElemId(matchFolder);
    $(`#${folderElemId}`)
      .attr("data-run-id", matchFolder["run_id"])
      .attr("data-query", matchFolder["query"])
      .addClass("active")
      .addClass("show")
      .siblings()
      .removeClass("active")
      .removeClass("show");
  });
}

function renderMainContent(projectRow) {
  let project = projectRow["project"];
  let [author, package] = project.split("_latest")[0].split("__");
  let tag = projectRow["commit_id"];

  // Render title
  $("#title-author").text(author);
  $("#title-package").text(package);
  $("#title-tag").text(tag);
  $("#project-copy").attr("aria-data", project);

  // Render links
  let githubUrl = projectRow["git_url"].split("/");
  let githubAuthor = githubUrl[3];
  let githubProject = githubUrl[4].split(".git")[0];
  $("#title-author").attr("href", `https://github.com/${githubAuthor}`);
  $("#title-package").attr("href", `https://github.com/${githubAuthor}/${githubProject}`);
  $("#title-tag").attr("href", `https://github.com/${githubAuthor}/${githubProject}/tree/${tag}`);

  // Render NVD
  $("#title-nvd-link").attr("href", `#`);

  // Fetch results
  loadResults(projectRow)
}

function fold(list, init, func, onFinish) {
  function recurse(index, agg) {
    if (index < list.length) {
      let elem = list[index];
      func(elem, index, agg, (new_agg) => {
        recurse(index + 1, new_agg)
      })
    } else {
      onFinish(agg);
    }
  }

  recurse(0, init)
}

function fetchProjects(callback) {
  fetchCSV(PROJECTS_CSV, callback)
}

function fetchFile(file, callback) {
  $.ajax({
    url: file,
    type: "GET",
    success: (fileContent) => {
      callback(fileContent)
    },
    error: () => {
      callback(null)
    }
  })
}

function fetchCSV(file, callback) {
  $.ajax({
    url: file,
    type: "GET",
    success: (csvContent) => {
      let parsedResult = Papa.parse(csvContent, { header: true });
      let data = parsedResult.data;
      callback(data);
    }
  })
}

function fetchJSON(file, callback) {
  $.ajax({
    url: file,
    type: "GET",
    dataType: "json",
    success: (content) => {
      callback(content);
    },
    error: () => {
      callback(null);
    }
  })
}

function fetchChildDirectories(dir, callback) {
  $.ajax({
    url: dir,
    type: "GET",
    success: (data) => {
      const regexp = /<a href="(\S+)\/">/g;
      let results = [...data.matchAll(regexp)].map((d) => d[1]);
      callback(results);
    },
    error: () => {
      callback(null);
    },
  });
}

function fetchChildFiles(dir, callback) {
  $.ajax({
    url: dir,
    type: "GET",
    success: (data) => {
      const regexp = /<a href="(\S+\.\S+)">/g;
      let results = [...data.matchAll(regexp)].map((d) => d[1]);
      callback(results);
    },
    error: () => {
      callback(null);
    },
  });
}

function fetchOutputDirectory(dbName, callback) {
  fetchChildDirectories(`${OUTPUT_DIR}/${dbName}`, (runIds) => {
    if (runIds) {
      fold(runIds, [], (runId, _, results, cb1) => {
        fetchChildDirectories(`${OUTPUT_DIR}/${dbName}/${runId}`, (queries) => {
          if (queries) {
            fold(queries, results, (query, _, results, cb2) => {
              if (QUERY_NAMES[query]) {
                fetchChildFiles(`${OUTPUT_DIR}/${dbName}/${runId}/${query}`, (files) => {
                  if (files.indexOf("results.sarif") >= 0) {
                    cb2([...results, { "run_id": runId, "query": query }]);
                  } else {
                    cb2(results);
                  }
                })
              } else {
                cb2(results);
              }
            }, cb1);
          } else {
            cb1(results)
          }
        });
      }, callback);
    } else {
      callback([])
    }
  });
}

function fetchClassLocations(dbName, runId, callback) {
  fetchCSV(`${OUTPUT_DIR}/${dbName}/${runId}/fetch_class_locs/results.csv`, callback)
}

function fetchFuncLocations(dbName, runId, callback) {
  fetchCSV(`${OUTPUT_DIR}/${dbName}/${runId}/fetch_func_locs/results.csv`, callback)
}

function renderSearchBar(cveList, projectTags) {
  $("#search-result-list").html(cveList.map(cveRow => {
    let cve = cveRow["cve"];
    if (!cveRow["cwe"]) {
      return "";
    }
    let relevantProjectTags = projectTags.filter(r => r["cve"] == cve);
    if (relevantProjectTags.length == 0) {
      return "";
    }
    let projectTag = relevantProjectTags[0];
    let project = projectTag["project"];
    let [author, package] = project.split("_CVE-")[0].split("__");
    let tag = projectTag["tag"];
    let cweBadges = cveRow["cwe"].split(";").map(renderCWEBadge).join("");
    return `
      <a href="${generateHrefURL(null, cve)}" class="list-group-item list-group-item-action py-3 lh-tight" hidden="hidden">
        <div class="d-flex w-100 align-items-center justify-content-between">
          <strong class="mb-1 cve">${cve}</strong>
          <small class="cwes">${cweBadges}</small>
        </div>
        <div class="col-10 mb-1 small">
          <span class="author">${author}</span> / <span class="package">${package}</span> / <span class="tag">${tag}</span>
          <span class="project" hidden="hidden">${project}</span>
        </div>
      </a>
    `;
  }).join(""))
}

function matchSearchText(searchText, originalTexts) {
  let searchParts = searchText.split(" ").map(part => part.trim().toLowerCase()).filter(part => part != "");
  for (let part of searchParts) {
    let hasMatch = false;
    for (let originalText of originalTexts) {
      if (originalText.toLowerCase().indexOf(part) >= 0) {
        hasMatch = true;
      }
    }
    if (!hasMatch) {
      return false;
    }
  }
  return true;
}

function initializeSearchInputHandler() {
  const myModalEl = document.getElementById("search-modal");
  let collapseIsHidden = true;

  // When the modal is hidden, we collapse the
  myModalEl.addEventListener('hidden.bs.modal', event => {
    new bootstrap.Collapse("#search-result-collapse", { hide: true });
    collapseIsHidden = true;
    $("#search-input").blur();
  });

  // When the modal is shown, we focus on the search bar
  myModalEl.addEventListener('shown.bs.modal', event => {
    $("#search-input").focus();
  });

  // When the search bar is changed
  $('#search-input').on('input', function (event) {
    let searchText = $(this).val().toLowerCase();
    if (searchText == "") {
      new bootstrap.Collapse("#search-result-collapse", { hide: true });
      collapseIsHidden = true;
    } else {
      // Check
      if (collapseIsHidden) {
        new bootstrap.Collapse("#search-result-collapse", { show: true });
        collapseIsHidden = false;
      }

      // Do actual filtering
      $("#search-result-list a").each(function (index) {
        let elem = $(this);
        let allOriginalTextToSearch = [];

        // Add CVE
        let cve = elem.find(".cve").text().toLowerCase();
        allOriginalTextToSearch.push(cve);

        // Add CWE
        elem.find(".cwe span").each(function (index) {
          allOriginalTextToSearch.push($(this).text());
        });

        // Add Project, author, and tag
        allOriginalTextToSearch.push(elem.find(".package").text().toLowerCase());
        allOriginalTextToSearch.push(elem.find(".author").text().toLowerCase());
        allOriginalTextToSearch.push(elem.find(".tag").text().toLowerCase());
        allOriginalTextToSearch.push(elem.find(".project").text().toLowerCase());

        // Get final search result
        if (matchSearchText(searchText, allOriginalTextToSearch)) {
          elem.removeAttr("hidden");
        } else {
          elem.attr("hidden", "hidden");
        }
      })
    }
  });
}

function renderPage(projects) {
  // Load sidebar
  renderSidebar(projects);

  // Load search bar
  renderSearchBar(projects);
  initializeSearchInputHandler();

  // Load main content
  let project = getQueriedProjectFromURL();
  if (project != null) {
    let maybeProjectRows = projects.filter((row) => row["project"] == project);
    if (maybeProjectRows.length > 0) {
      let projectRow = maybeProjectRows[0];
      renderMainContent(projectRow);
    }
  }
}

function loadPage() {
  fetchProjects((projects) => {
    renderPage(projects);
  })
}

loadPage();
