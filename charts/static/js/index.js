$(document).ready(function () {

    const speed_context = document.getElementById('speed_canvas').getContext('2d');
    const packets_context = document.getElementById('packets_canvas').getContext('2d');
    const protocols_context = document.getElementById('protocols_canvas').getContext('2d');
    const unique_context = document.getElementById('unique_canvas').getContext('2d');

    const speed_lineChart = new Chart(speed_context, speed_config);
    const packets_lineChart = new Chart(packets_context, packets_config);
    const protocols_lineChart = new Chart(protocols_context, protocols_config);
    const unique_lineChart = new Chart(unique_context, unique_config);

    const source = new EventSource("/chart-data");

    source.onmessage = function (event) {
        const data = JSON.parse(event.data);

        if (speed_config.data.labels.length === 20) {
            speed_config.data.labels.shift();
            speed_config.data.datasets[0].data.shift();

            packets_config.data.labels.shift();
            packets_config.data.datasets[0].data.shift();
            packets_config.data.datasets[1].data.shift();

            protocols_config.data.labels.shift();
            protocols_config.data.datasets[0].data.shift();
            protocols_config.data.datasets[1].data.shift();
            protocols_config.data.datasets[2].data.shift();
            protocols_config.data.datasets[3].data.shift();

            unique_config.data.labels.shift();
            unique_config.data.datasets[0].data.shift();
            unique_config.data.datasets[1].data.shift();
        }
        speed_config.data.labels.push(data.time);
        speed_config.data.datasets[0].data.push(data.speed);
        speed_lineChart.update();


        // Packets
        packets_config.data.labels.push(data.time);
        packets_config.data.datasets[0].data.push(data.passed);
        packets_config.data.datasets[1].data.push(data.dropped);
        packets_lineChart.update();

        // Protocols
        protocols_config.data.labels.push(data.time);
        protocols_config.data.datasets[0].data.push(data.tcp);
        protocols_config.data.datasets[1].data.push(data.udp);
        protocols_config.data.datasets[2].data.push(data.icmp);
        protocols_config.data.datasets[3].data.push(data.other);
        protocols_lineChart.update();

        // Unique
        unique_config.data.labels.push(data.time);
        unique_config.data.datasets[0].data.push(data.ips);
        unique_config.data.datasets[1].data.push(data.ports);
        unique_lineChart.update();
    }
});