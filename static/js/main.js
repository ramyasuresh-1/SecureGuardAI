document.addEventListener('DOMContentLoaded', () => {
  const counters = document.querySelectorAll('.counter');

  counters.forEach((counter) => {
    const target = Number(counter.getAttribute('data-count'));
    let current = 0;
    const increment = target / 40;

    const update = () => {
      current += increment;
      if (current < target) {
        counter.textContent = Math.ceil(current);
        requestAnimationFrame(update);
      } else {
        counter.textContent = target;
      }
    };

    update();
  });

  const savedTheme = localStorage.getItem('secureguard-theme');
  if (savedTheme === 'light') {
    document.body.classList.remove('dark-theme');
  } else {
    document.body.classList.add('dark-theme');
  }

  const themeToggle = document.querySelector('[data-theme-toggle]');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      document.body.classList.toggle('dark-theme');
      const isDark = document.body.classList.contains('dark-theme');
      localStorage.setItem('secureguard-theme', isDark ? 'dark' : 'light');
      const icon = themeToggle.querySelector('i');
      if (icon) {
        icon.className = isDark ? 'fa-solid fa-moon' : 'fa-solid fa-sun';
      }
    });
  }

  const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
  const sidebar = document.querySelector('.sidebar');
  if (sidebarToggle && sidebar) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('sidebar-collapsed');
    });
  }

  const drawChart = (canvasId, config) => {
    const canvas = document.getElementById(canvasId);
    if (!canvas) {
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return;
    }

    new Chart(ctx, config);
  };

  drawChart('securityScoreChart', {
    type: 'doughnut',
    data: {
      labels: ['Secure', 'At Risk', 'Monitoring'],
      datasets: [{
        data: [78, 14, 8],
        backgroundColor: ['#00e5ff', '#7c4dff', '#f59e0b'],
        borderWidth: 0,
      }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      cutout: '70%',
    },
  });

  drawChart('threatRadarChart', {
    type: 'radar',
    data: {
      labels: ['Identity', 'Passwords', 'Devices', 'Cloud', 'Phishing'],
      datasets: [{
        data: [82, 74, 68, 79, 72],
        backgroundColor: 'rgba(0, 229, 255, 0.25)',
        borderColor: '#00e5ff',
        pointBackgroundColor: '#00e5ff',
        pointBorderColor: '#fff',
        pointRadius: 4,
      }],
    },
    options: {
      responsive: true,
      scales: { r: { suggestedMin: 50, suggestedMax: 100 } },
    },
  });

  drawChart('trendLineChart', {
    type: 'line',
    data: {
      labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
      datasets: [{
        data: [68, 72, 74, 77, 81, 85],
        borderColor: '#00e5ff',
        backgroundColor: 'rgba(0, 229, 255, 0.2)',
        tension: 0.35,
        fill: true,
      }],
    },
    options: { responsive: true, plugins: { legend: { display: false } } },
  });

  drawChart('activityBarChart', {
    type: 'bar',
    data: {
      labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
      datasets: [{
        data: [12, 18, 10, 19, 15],
        backgroundColor: ['#00e5ff', '#7c4dff', '#00e5ff', '#7c4dff', '#00e5ff'],
      }],
    },
    options: { responsive: true, plugins: { legend: { display: false } } },
  });

  drawChart('distributionPieChart', {
    type: 'pie',
    data: {
      labels: ['Strong', 'Moderate', 'Weak'],
      datasets: [{
        data: [55, 30, 15],
        backgroundColor: ['#00e5ff', '#7c4dff', '#f59e0b'],
      }],
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom' } } },
  });

  drawChart('gaugeChart', {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [88, 12],
        backgroundColor: ['#00e5ff', 'rgba(255,255,255,0.08)'],
        borderWidth: 0,
      }],
    },
    options: {
      responsive: true,
      cutout: '75%',
      plugins: { legend: { display: false } },
    },
  });
});
