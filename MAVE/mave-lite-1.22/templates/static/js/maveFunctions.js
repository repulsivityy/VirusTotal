function resetIntelligenceMatrix()
{
    wideArray = [0, 0, 0, 0];
    confirmedArray = [0, 0, 0, 0];
    availableArray = [0, 0, 0, 0];
    //anticipatedArray = [0, 0, 0, 0];
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
        /*
        else if(12<=index && index<16)
        {
            $(this).html(anticipatedArray[index%12]);
        }
        */
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
        if(null != eRating && undef != eRating)
        {
            eRating = eRating.toLowerCase();
        }

        rRating = reportsData['RiskRating'];
        if(null != rRating && undef != rRating)
        {
            rRating = rRating.toLowerCase();
        }

        if('no known' == eRating)
        {
            if('low' == rRating)
            {
                noknownArray[0]++;
            }
            else if('medium' == rRating)
            {
                noknownArray[1]++;
            }
            else if('high' == rRating)
            {
                noknownArray[2]++;
            }
            else if('critical' == rRating)
            {
                noknownArray[3]++;
            }
        }
        /*
        else if('anticipated' == eRating)
        {
            if('low' == rRating)
            {
                anticipatedArray[0]++;
            }
            else if('medium' == rRating)
            {
                anticipatedArray[1]++;
            }
            else if('high' == rRating)
            {
                anticipatedArray[2]++;
            }
            else if('critical' == rRating)
            {
                anticipatedArray[3]++;
            }
        }
        */
        else if('available' == eRating)
        {
            if('low' == rRating)
            {
                availableArray[0]++;
            }
            else if('medium' == rRating)
            {
                availableArray[1]++;
            }
            else if('high' == rRating)
            {
                availableArray[2]++;
            }
            else if('critical' == rRating)
            {
                availableArray[3]++;
            }
        }
        else if('confirmed' == eRating)
        {
            if('low' == rRating)
            {
                confirmedArray[0]++;
            }
            else if('medium' == rRating)
            {
                confirmedArray[1]++;
            }
            else if('high' == rRating)
            {
                confirmedArray[2]++;
            }
            else if('critical' == rRating)
            {
                confirmedArray[3]++;
            }
        }
        else if('wide' == eRating)
        {
            if('low' == rRating)
            {
                wideArray[0]++;
            }
            else if('medium' == rRating)
            {
                wideArray[1]++;
            }
            else if('high' == rRating)
            {
                wideArray[2]++;
            }
            else if('critical' == rRating)
            {
                wideArray[3]++;
            }
        }
    }
    showIntelligenceMatrix();
}

function getTitleSplit(title)
{
    let reportTitle = blankLiteral;
    for(let titleCounter=0; titleCounter<(title.length/titleTerminationLength); titleCounter++)
    {
        if(blankLiteral != reportTitle)
            reportTitle = reportTitle.concat("<br>");

        if((titleCounter+1)*titleTerminationLength > title.length)
            reportTitle = reportTitle.concat(title.substring(titleCounter*titleTerminationLength));
        else
            reportTitle = reportTitle.concat(title.substring(titleCounter*titleTerminationLength, (titleCounter+1)*titleTerminationLength));
    }
    return reportTitle;
}

function getVulnId(cveVuln)
{
    colon_index = cveVuln.indexOf(":");
    if(colon_index != -1)
    {
        vuln_id = cveVuln.substring(colon_index+1)
        return vuln_id;
    }
    else
    {
        return blankLiteral;
    }
}

function displayList(inputList, row, type)
{
    let displayThis = blankLiteral;
    for(ctr in inputList)
    {
        if(blankLiteral != displayThis)
            displayThis = displayThis.concat(',<br>')

        if(ctr<5)
        {
            if(type != 'vector')
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
            let mandiantAdvantageUrl = 'https://advantage.mandiant.com/cve/'+getVulnId(row[0]);
            displayThis = displayThis.concat('...<br>');
            displayThis = displayThis.concat("<a target='_blank' title ='"+mandiantAdvantageUrl+"' href='"+mandiantAdvantageUrl+"'> Show more >> </a>");
            break;
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
            targets: [8, 9, 10, 11, 12, 13, 14]
        },
        {
            targets: [0],
            "visible": isDefaultVisible('CveId'),
            "width": "10%",
            //data: 'CveId',
            "searchable": true,
            "sortable": true,
            'render': function (data, type, row){
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    colon_index = data.indexOf(":");
                    if(colon_index != -1)
                    {
                        cve_id = data.substring(0, colon_index)
                        vuln_id = data.substring(colon_index+1)
                        let mandiantAdvantageUrl = 'https://advantage.mandiant.com/cve/'+vuln_id
                        return "<a target='_blank' title ='"+mandiantAdvantageUrl+"' href='"+mandiantAdvantageUrl+"'>"+cve_id+"</a>";    
                    }
                }
                if('sort' == type)
                {
                    colon_index = data.indexOf(":");
                    if(colon_index != -1)
                    {
                        cve_id = data.substring(0, colon_index) 
                        return ((null != cve_id && blankLiteral!= cve_id)?cve_id:'-1');
                    }
                }
            }
        },
        {
            "targets": [1],
            "visible": isDefaultVisible('ExploitRating'),
            //data: 'ExploitRating',
            "searchable": true,
            "sortable": true,
            'render': function (data, type, row){
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    return data;
                }
                if('sort' == type)
                {
                    return ((null != data && blankLiteral!= data && hyphen != data)?exploitRatingMap.get(data.toLowerCase()):'-1');
                }
            },
        },
        {
            targets: [2],
            "visible": isDefaultVisible('RiskRating'),
            //data: 'RiskRating',
            "searchable": true,
            "sortable": true,
            'render': function (data, type, row){
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    return data;
                }
                if('sort' == type)
                {
                    return ((null != data && blankLiteral!= data && hyphen!= data)?riskRatingMap.get(data.toLowerCase()):'-1');
                }
            },
        },
        {
            "targets": [3],
            "visible": isDefaultVisible('UserInteraction'),
            //data: 'UserInteraction',
            "searchable": true,
            "sortable": true,
            'render': function (data, type, row){
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    return data;
                }
                if('sort' == type)
                {
                    return ((null != data && blankLiteral!= data && hyphen!= data)?userInteractionMap.get(data.toLowerCase()):'-1');
                }
            },
        },
        {
            "targets": [4],
            "visible": isDefaultVisible('AssociatedActors'),
            //data: 'AssociatedActors',
            'render': function (data, type, row){
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    replaced_data = data.replace(/'/g, '"');
                    return displayList(JSON.parse(replaced_data), row, "actors");
                }
            },

            "searchable": true,
            "sortable":false,
        },
        {
            "targets": [5],
            "visible": isDefaultVisible('AssociatedMalware'),
            //data: 'AssociatedMalware',
            'render': function (data, type, row){
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    replaced_data = data.replace(/'/g, '"');
                    return displayList(JSON.parse(replaced_data), row, "malware");
                }
            },
            "searchable": true,
            "sortable":false,
        },
        {
            "targets": [6],
            "visible": isDefaultVisible('Title'),
            //"width": "20%",
            //data: 'Title',
            "render":
            function (data, type, row)
            {
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    //return getTitleSplit(data);
                    return data;
                }
            },
            "searchable": false,
            "sortable":false,
        },
        {
            "targets": [7],
            "visible": isDefaultVisible('ExploitationVector'),
            //"width": "8%",
            //data: 'ExploitationVector',
            "render":
            function (data, type, row)
            {
                if('display' == type || 'filter' == type || 'type' == type)
                {
                    return displayList(eval(data), row, "vector");
                }
            },
            "searchable": true,
            "sortable":false,
        },
        {
            "targets": [8],
            "visible": isDefaultVisible('PublishedDate'),
            //data: 'PublishedDate',
            "searchable": false,
            "sortable": false,
        },
        {
            "targets": [9],
            "visible": isDefaultVisible('DateOfDisclosure'),
            //data: 'DateOfDisclosure',
            "searchable": false,
            "sortable": false,
        },
        {
            "targets": [10],
            "visible": isDefaultVisible('WasZeroDay'),
            //data: 'WasZeroDay',
            "searchable": false,
            "sortable": false,
        },
        {
            "targets": [11],
            "visible": isDefaultVisible('V3_BaseScore'),
            //data: 'V3_BaseScore',
            "searchable": false,
            "sortable": false,
        },
        {
            "targets": [12],
            "visible": isDefaultVisible('V3_TemporalScore'),
            //data: 'V3_TemporalScore',
            "searchable": false,
            "sortable": false,
        },
        {
            "targets": [13],
            "visible": isDefaultVisible('V2_BaseScore'),
            //data: 'V2_BaseScore',
            "searchable": false,
            "sortable": false,
        },
        {
            "targets": [14],
            "visible": isDefaultVisible('V2_TemporalScore'),
            //data: 'V2_TemporalScore',
            "searchable": false,
            "sortable": false,
        }
    ];
    return columnDef;
}

$('#divShowTblHdr').children().on('click', function (e) {
    e.preventDefault();
    // Get the column API object
    columnNumbers = $(this).attr('data-column').split("-")
    let preSelectedCount = $('#divShowTblHdr').children('a:not(.strikeThrough)').length;
    let alwaysShowCount = 4;

    if((alwaysShowCount + preSelectedCount)>9 && $(e.target).hasClass('strikeThrough'))
    {
       $("#msgDisplayStage").html("Only 10 columns can be shown at a given time. Please unselect a few to view new columns.");
       return;
    }
    else
    {
        $("#msgDisplayStage").html("");
    }
    for(let col in columnNumbers)
    {
        var column = datatable.column(columnNumbers[col]);
        // Toggle the visibility
        column.visible(!column.visible());
        datatable.columns.adjust().draw();
    }
    if($(this).hasClass('strikeThrough'))
    {
        $(this).removeClass('strikeThrough');
    }
    else
    {
        $(this).addClass('strikeThrough');
    }
});

function strikeInvisibleColumns()
{
    $('#divShowTblHdr').children('a').each(function () {
        (!(combinedColumns.includes(this.id) || defaultVisibleColumns.includes(this.id))) ? ($(this).addClass('strikeThrough')):($(this).removeClass('strikeThrough'));
    });
    $("#msgDisplayStage").html("");
}

$(document).click(function (e)
{
    var container = $("#msgDisplayStage");
    if (!container.is(e.target) && container.has(e.target).length === 0 && "divShowTblHdr" != e.target.parentElement.getAttribute("id"))
    {
        container.html("");
    }
});


