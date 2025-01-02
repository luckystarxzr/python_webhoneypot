document.addEventListener('DOMContentLoaded', function() {
    // 图表配置
    const chartConfig = {
        // 通用配置
        common: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        font: {
                            family: "'Microsoft YaHei', 'PingFang SC', sans-serif"
                        }
                    }
                },
                tooltip: {
                    titleFont: {
                        family: "'Microsoft YaHei', 'PingFang SC', sans-serif"
                    },
                    bodyFont: {
                        family: "'Microsoft YaHei', 'PingFang SC', sans-serif"
                    }
                }
            }
        },
        // 饼图特定配置
        pie: {
            plugins: {
                title: {
                    display: true,
                    text: '攻击类型分布'
                }
            }
        },
        // 柱状图特定配置
        bar: {
            plugins: {
                title: {
                    display: true,
                    text: '攻击者分布'
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        font: {
                            family: "'Microsoft YaHei', 'PingFang SC', sans-serif"
                        }
                    }
                },
                x: {
                    ticks: {
                        font: {
                            family: "'Microsoft YaHei', 'PingFang SC', sans-serif"
                        }
                    }
                }
            }
        }
    };

    // 初始化图表
    function initializeCharts() {
        try {
            fetch('/api/dashboard/stats')
                .then(response => {
                    if (!response.ok) {
                        throw new Error('网络请求失败');
                    }
                    return response.json();
                })
                .then(data => {
                    const attackTypesData = data.attack_types || {};
                    const topAttackersData = data.top_attackers || {};

                    // 攻击类型饼图
                    const attackTypesElement = document.getElementById('attackTypesChart');
                    if (attackTypesElement) {
                        const ctx = attackTypesElement.getContext('2d');
                        new Chart(ctx, {
                            type: 'pie',
                            data: {
                                labels: Object.keys(attackTypesData),
                                datasets: [{
                                    data: Object.values(attackTypesData),
                                    backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF']
                                }]
                            },
                            options: {
                                ...chartConfig.common,
                                ...chartConfig.pie
                            }
                        });
                    }

                    // 攻击者柱状图
                    const topAttackersElement = document.getElementById('topAttackersChart');
                    if (topAttackersElement) {
                        const ctx = topAttackersElement.getContext('2d');
                        new Chart(ctx, {
                            type: 'bar',
                            data: {
                                labels: Object.keys(topAttackersData),
                                datasets: [{
                                    label: '攻击次数',
                                    data: Object.values(topAttackersData),
                                    backgroundColor: '#36A2EB'
                                }]
                            },
                            options: {
                                ...chartConfig.common,
                                ...chartConfig.bar
                            }
                        });
                    }
                })
                .catch(error => {
                    console.error('加载图表数据失败:', error);
                    // 可以在这里添加用户提示
                    const errorDiv = document.createElement('div');
                    errorDiv.className = 'alert alert-danger';
                    errorDiv.textContent = '加载图表数据失败，请刷新页面重试';
                    document.querySelector('.container').prepend(errorDiv);
                });
        } catch (error) {
            console.error('初始化图表失败:', error);
        }
    }

    // 启动初始化
    initializeCharts();
});