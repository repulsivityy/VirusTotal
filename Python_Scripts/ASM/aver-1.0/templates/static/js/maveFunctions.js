const severityMap = {
    '1': 'Critical',
    '2': 'High',
    '3': 'Medium',
    '4': 'Low',
    '5': 'Informational'
};

function resetIntelligenceMatrix()
{
    wideArray = [0, 0, 0, 0];
    confirmedArray = [0, 0, 0, 0];
    availableArray = [0, 0, 0, 0];
    noknownArray = [0, 0, 0, 0];
}

function isDefaultVisible(columnName)
{
    return defaultVisibleColumns.includes(columnName);
}

function showIntelligenceMatrix()
{
    $('#gridContainer').show();
    $('.grid').each(function(index)
    {
        if(0<=index && index<4)
        {
            $(this).html(wideArray[index]);
        }
        else if(4<=index && index<8)
        {
            $(this).html(confirmedArray[index%4]);
        }
        else if(8<=index && index<12)
        {
            $(this).html(availableArray[index%8]);
        }
        else if(12<=index && index<16)
        {
            $(this).html(noknownArray[index%12]);
        }
    });
}

function buildIntelligenceMatrix(allReports)
{
    let eRating = '', rRating ='';
    for(let rptCtr = 0; rptCtr < allReports.length; rptCtr++)
    {
        reportsData = allReports[rptCtr];
        eRating = reportsData['ExploitRating'];
        if(eRating != null && eRating != undefined)
        {
            eRating = eRating.toLowerCase();
        }

        rRating = reportsData['RiskRating'];
        if(rRating != null && rRating != undefined)
        {
            rRating = rRating.toLowerCase();
        }

        if('no known' == eRating)
        {
            if('low' == rRating) { noknownArray[0]++; }
            else if('medium' == rRating) { noknownArray[1]++; }
            else if('high' == rRating) { noknownArray[2]++; }
            else if('critical' == rRating) { noknownArray[3]++; }
        }
        else if('available' == eRating)
        {
            if('low' == rRating) { availableArray[0]++; }
            else if('medium' == rRating) { availableArray[1]++; }
            else if('high' == rRating) { availableArray[2]++; }
            else if('critical' == rRating) { availableArray[3]++; }
        }
        else if('confirmed' == eRating)
        {
            if('low' == rRating) { confirmedArray[0]++; }
            else if('medium' == rRating) { confirmedArray[1]++; }
            else if('high' == rRating) { confirmedArray[2]++; }
            else if('critical' == rRating) { confirmedArray[3]++; }
        }
        else if('wide' == eRating)
        {
            if('low' == rRating) { wideArray[0]++; }
            else if('medium' == rRating) { wideArray[1]++; }
            else if('high' == rRating) { wideArray[2]++; }
            else if('critical' == rRating) { wideArray[3]++; }
        }
    }
    showIntelligenceMatrix();
}

function getVulnId(cveVuln)
{
    let colon_index = cveVuln.indexOf(":");
    if(colon_index != -1)
    {
        return cveVuln.substring(colon_index+1);
    }
    return "";
}

function displayList(inputList, row, type)
{
    let displayThis = "";
    if (!Array.isArray(inputList)) { return inputList; } // Safety check

    for(let ctr in inputList)
    {
        if(displayThis !== "")
            displayThis = displayThis.concat(',<br>');

        if(ctr < 5)
        {
            if(type != 'vector' && inputList[ctr]['Weblink'])
            {
                displayThis = displayThis.concat('<a target="_blank" href="'+inputList[ctr]['Weblink']+'">'+inputList[ctr]['Name']+'</a>');
            }
            else
            {
                displayThis = displayThis.concat(inputList[ctr]);
            }
        }
        else
        {
            // --- MODIFIED SECTION ---
            let finalUrl = BASE_VULN_URL; // Start with the global base URL
            
            // Append the correct identifier based on the platform
            if (BASE_VULN_URL.includes("advantage.mandiant.com")) {
                finalUrl += getVulnId(row['CveId']); // Use vulnerability ID for Advantage
            } else {
                let cve_id_only = row['CveId'].split(":")[0]; // Get just the CVE part
                finalUrl += cve_id_only; // Use CVE ID for GTI
            }
            
            displayThis = displayThis.concat('...<br>');
            displayThis = displayThis.concat("<a target='_blank' title='" + finalUrl + "' href='" + finalUrl + "'> Show more >> </a>");
            break;
            // --- END MODIFIED SECTION ---
        }
    }
    return displayThis;
}


function createColumnDefs()
{
    let columnDef =
    [
        {
            className: "tblCenterText",
            targets: [7, 12, 13, 14, 15, 16, 17, 18]
        },
        {
            targets: [0], // This is the CVE-ID column
            'render': function (data, type, row){
                if(type === 'display') {
                    let colon_index = data.indexOf(":");
                    if(colon_index != -1) {
                        let cve_id = data.substring(0, colon_index);
                        let vuln_id = data.substring(colon_index+1);
                
                        // Use the global variable passed from the Python script.
                        // It will be either the GTI or Advantage URL.
                        let finalUrl = BASE_VULN_URL; 
                
                        // Append the correct identifier based on which URL is being used.
                        if (BASE_VULN_URL.includes("advantage.mandiant.com")) {
                            finalUrl += vuln_id; // Use vulnerability ID for Advantage
                        } else {
                            finalUrl += cve_id; // Use CVE ID for GTI
                        }
                
                        return `<a target='_blank' title='${finalUrl}' href='${finalUrl}'>${cve_id}</a>`;
                    }
                }
                // For sorting, filtering, etc., return the raw data
                return data;
            }
        },
        {
            targets: [1], // Exploit Rating
            'render': function (data, type, row){
                if(type === 'display' || type === 'filter') {
                    return data;
                }
                if(type === 'sort' && data != null) {
                    return exploitRatingMap.get(data.toLowerCase()) || -1;
                }
                return data;
            },
        },
        {
            targets: [2], // Risk Rating
            'render': function (data, type, row){
                if(type === 'display' || type === 'filter') {
                    return data;
                }
                if(type === 'sort' && data != null) {
                    return riskRatingMap.get(data.toLowerCase()) || -1;
                }
                return data;
            },
        },
        {
            targets: [3], // Issue Name
            'render': function (data, type, row) {
            // 'data' = IssueName
            // 'row' = the full row object

            var issueName = data || 'N/A';
            var issueUID = row.IssueUID; // Get the new IssueUID field from our Python change

            if (type === 'display') {
                // If we have the IssueUID, build the link to the ASM issue page
                if (issueUID) {
                    let asmLink = `https://asm.advantage.mandiant.com/issues/${issueUID}`;
                    return `<a href="${asmLink}" target="_blank">${issueName}</a>`;
                }

                // Fallback: If no UID, just return the plain text.
                return issueName;
            }

            // For sorting/filtering, just use the plain issue name text.
            return data;
            }
        },

        {
            targets: [4], // Entity Name
            'render': function (data, type, row) {
                // 'data' = EntityName
                // 'row' = full row object
            
                var entityName = data || 'N/A';
                var entityUID = row.EntityUID; // <-- Get the correct field: EntityUID
            
                if (type === 'display') {
                    // If we have the UID, build the ASM Advantage link
                    if (entityUID) {
                        // Use your requested URL format
                        let asmLink = `https://asm.advantage.mandiant.com/entities/${entityUID}`;
                        return `<a href="${asmLink}" target="_blank">${entityName}</a>`;
                    }
                
                    // FALLBACK: If no UID, check if the name itself is a clickable URL
                    if (entityName.startsWith('http://') || entityName.startsWith('https://')) {
                        return `<a href="${entityName}" target="_blank">${entityName}</a>`;
                    }

                    // If neither, just return the plain text.
                    return entityName;
                }
            
                // For sorting/filtering, just use the plain entity name.
                return data;
            }
        },
        
        {
            targets: [5], // Issue Severity
            render: function (data, type, row) {
                // For display, convert the number to text using the map
                if (type === 'display') {
                    return severityMap[String(data)] || data;
                }
                // For sorting and filtering, use the original numeric data
                return data;
            }
        },
        {
            targets: [6], // Issue Confidence
            'render': function (data, type, row){
                if (type === 'display') {
                    return data; // Show the string "High", "Medium", etc.
                }
                if (type === 'sort') {
                    // Use the map from maveVarInit.js to return a number for sorting
                    return (data && issueConfidenceMap.has(data.toLowerCase())) ? issueConfidenceMap.get(data.toLowerCase()) : -1;
                }
                // For all other types (filter, etc.), return the raw data (string)
                return data;
            }
        },
        {
            targets: [7], // User Interaction
            'render': function (data, type, row){
                if(type === 'display' || type === 'filter') {
                    return data;
                }
                if(type === 'sort' && data != null) {
                    return userInteractionMap.get(data.toLowerCase()) || -1;
                }
                return data;
            },
        },

        // THESE ARE THE ROBUST RENDERERS FOR ARRAY COLUMNS (FIXES THE "WORKS ONCE" BUG)
        {
            targets: [8], // Associated Actors
            'render': function (data, type, row){
                if (type === 'display') { 
                    return displayList(data, row, "actors"); // This returns HTML
                }
                
                // For ALL other types (sort, filter, auto, cache, etc.):
                // Return a simple, flat string. NEVER return the raw array object.
                if (Array.isArray(data)) {
                    return data.map(item => (item && item.Name) ? item.Name : "").join(', ');
                }
                
                return data; // Fallback for null/empty data
            },
        },
        {
            targets: [9], // Associated Malware
            'render': function (data, type, row){
                if (type === 'display') { 
                    return displayList(data, row, "malware"); // This returns HTML
                }
                
                // For ALL other types: Return a simple, flat string.
                if (Array.isArray(data)) {
                    return data.map(item => (item && item.Name) ? item.Name : "").join(', ');
                }

                return data;
            },
        },
        { targets: [10], }, // Title
        {
            targets: [11], // Exploitation Vector(s)
            "render": function (data, type, row) {
                if (type === 'display') { 
                    return displayList(data, row, "vector"); // This returns HTML
                }
                
                // For ALL other types: Return a simple, flat string.
                if (Array.isArray(data)) {
                    // This is an array of strings
                    return data.join(', ');
                }

                return data;
            },
        },
        
        // All remaining columns use default rendering
        { targets: [12], }, { targets: [13], }, { targets: [14], },
        { targets: [15], }, { targets: [16], }, { targets: [17], },
        { targets: [18], }
    ];
    return columnDef;
}

$('#divShowTblHdr').children().on('click', function (e) {
    e.preventDefault();
    let columnNumbers = $(this).attr('data-column').split("-");
    for(let col in columnNumbers)
    {
        let column = datatable.column(columnNumbers[col]);
        column.visible(!column.visible());
    }
    datatable.columns.adjust().draw();
    $(this).toggleClass('strikeThrough');
});

function strikeInvisibleColumns()
{
    $('#divShowTblHdr').children('a').each(function () {
        // This variable is expected to be defined in maveVarInit.js
        let isVisible = typeof defaultVisibleColumns !== 'undefined' && defaultVisibleColumns.includes(this.id);
        if (!isVisible) {
             $(this).addClass('strikeThrough');
             let columnNumbers = $(this).attr('data-column').split("-");
             for(let col in columnNumbers) {
                datatable.column(columnNumbers[col]).visible(false);
             }
        }
    });
    datatable.columns.adjust().draw();
}

$(document).click(function (e)
{
    var container = $("#msgDisplayStage");
    if (!container.is(e.target) && container.has(e.target).length === 0 && e.target.parentElement.getAttribute("id") !== "divShowTblHdr")
    {
        container.html("");
    }
});
