// -------------------------------------
//  SPEED CHART CONFIG
// -------------------------------------

const speed_config = {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: "Data transfer rate",
            backgroundColor: 'rgb(255, 99, 132)',
            borderColor: 'rgb(255, 99, 132)',
            data: [],
            fill: false,
        }],
    },
    options: {
        responsive: true,
        title: {
            display: true,
            text: 'Traffic load'
        },
        tooltips: {
            mode: 'index',
            intersect: false,
        },
        hover: {
            mode: 'nearest',
            intersect: true
        },
        scales: {
            xAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Time'
                }
            }],
            yAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Value (bytes/s)'
                }
            }]
        }
    }
};


// -------------------------------------
//  PACKETS CHART CONFIG
// -------------------------------------

const packets_config = {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: "Passed",
            backgroundColor: 'rgb(99, 99, 255)',
            borderColor: 'rgb(99, 99, 255)',
            data: [],
            fill: false,
        },
        {
            label: "Dropped",
            backgroundColor: 'rgb(255, 207, 51)',
            borderColor: 'rgb(255, 207, 51)',
            data: [],
            fill: false,
        }]
    },
    options: {
        responsive: true,
        title: {
            display: true,
            text: 'Packets'
        },
        tooltips: {
            mode: 'index',
            intersect: false,
        },
        hover: {
            mode: 'nearest',
            intersect: true
        },
        scales: {
            xAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Time'
                }
            }],
            yAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Number'
                }
            }]
        }
    }
};


// -------------------------------------
//  PROTOCOLS CHART CONFIG
// -------------------------------------

const protocols_config = {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: "TCP",
            backgroundColor: 'rgb(255, 99, 132)',
            borderColor: 'rgb(255, 99, 132)',
            data: [],
            fill: false,
        },
        {
            label: "UDP",
            backgroundColor: 'rgb(13, 255, 132)',
            borderColor: 'rgb(13, 255, 132)',
            data: [],
            fill: false,
        },
        {
            label: "ICMP",
            backgroundColor: 'rgb(255, 207, 51)',
            borderColor: 'rgb(255, 207, 51)',
            data: [],
            fill: false,
        },
        {
            label: "Others",
            backgroundColor: 'rgb(99, 99, 255)',
            borderColor: 'rgb(99, 99, 255)',
            data: [],
            fill: false,
        }],
    },
    options: {
        responsive: true,
        title: {
            display: true,
            text: 'Protocols'
        },
        tooltips: {
            mode: 'index',
            intersect: false,
        },
        hover: {
            mode: 'nearest',
            intersect: true
        },
        scales: {
            xAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Time'
                }
            }],
            yAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Value'
                }
            }]
        }
    }
};


// -------------------------------------
//  UNIQUENESS CHART CONFIG
// -------------------------------------

const unique_config = {
    type: 'line',
    data: {
        labels: [],
        datasets: [{
            label: "source IPs",
            backgroundColor: 'rgb(255, 99, 132)',
            borderColor: 'rgb(255, 99, 132)',
            data: [],
            fill: false,
        },
        {
            label: "destination PORTs",
            backgroundColor: 'rgb(99, 99, 255)',
            borderColor: 'rgb(99, 99, 255)',
            data: [],
            fill: false,
        }],
    },
    options: {
        responsive: true,
        title: {
            display: true,
            text: 'Number of unique'
        },
        tooltips: {
            mode: 'index',
            intersect: false,
        },
        hover: {
            mode: 'nearest',
            intersect: true
        },
        scales: {
            xAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Time'
                }
            }],
            yAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Number'
                }
            }]
        }
    }
};
