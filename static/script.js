/* ==========================================
   PhishGuard JavaScript
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ==========================
       Smooth Scroll
    ========================== */

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {

        anchor.addEventListener("click", function (e) {

            const target = document.querySelector(this.getAttribute("href"));

            if (!target) return;

            e.preventDefault();

            target.scrollIntoView({
                behavior: "smooth"
            });

        });

    });

    /* ==========================
       Scroll To Top
    ========================== */

    const scrollBtn = document.getElementById("scrollTopBtn");

    if (scrollBtn) {

        window.addEventListener("scroll", () => {

            if (window.scrollY > 250) {

                scrollBtn.style.display = "flex";

            } else {

                scrollBtn.style.display = "none";

            }

        });

        scrollBtn.addEventListener("click", () => {

            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });

        });

    }

    /* ==========================
       Navbar Shadow
    ========================== */

    const navbar = document.querySelector(".navbar");

    if (navbar) {

        window.addEventListener("scroll", () => {

            if (window.scrollY > 30) {

                navbar.style.boxShadow =
                    "0 10px 25px rgba(0,0,0,.25)";

            } else {

                navbar.style.boxShadow = "none";

            }

        });

    }

    /* ==========================
       Fade Animation
    ========================== */

    const observer = new IntersectionObserver(entries => {

        entries.forEach(entry => {

            if (entry.isIntersecting) {

                entry.target.classList.add("show");

            }

        });

    }, {
        threshold: 0.2
    });

    document.querySelectorAll(
        ".glass-card,.feature-card,.summary-card,.stats-card"
    ).forEach(el => {

        observer.observe(el);

    });

    /* ==========================
       Progress Bar Animation
    ========================== */

    const progress = document.querySelector(".progress-bar");

    if (progress) {

        const finalWidth =
            parseInt(progress.innerText) || 0;

        progress.style.width = "0%";

        let width = 0;

        const animation = setInterval(() => {

            if (width >= finalWidth) {

                clearInterval(animation);

            } else {

                width++;

                progress.style.width = width + "%";

                progress.innerHTML = width + "%";

            }

        }, 15);

    }

    /* ==========================
       Character Counter
    ========================== */

    const textarea = document.querySelector(".scanner-box");

    if (textarea) {

        const counter = document.createElement("small");

        counter.style.display = "block";
        counter.style.marginTop = "10px";
        counter.style.color = "#bbb";

        textarea.parentNode.appendChild(counter);

        const updateCounter = () => {

            counter.innerHTML =
                `${textarea.value.length} / 5000 Characters`;

        };

        updateCounter();

        textarea.addEventListener("input", updateCounter);

    }

    /* ==========================
       Button Loading Animation
    ========================== */

    const forms = document.querySelectorAll("form");

    forms.forEach(form => {

        form.addEventListener("submit", () => {

            const btn = form.querySelector("button");

            if (btn) {

                btn.disabled = true;

                btn.innerHTML =

                    '<span class="spinner-border spinner-border-sm me-2"></span>Analyzing...';

            }

        });

    });

    /* ==========================
       Auto Hide Alerts
    ========================== */

    setTimeout(() => {

        document.querySelectorAll(".alert").forEach(alert => {

            alert.style.transition = ".5s";

            alert.style.opacity = "0";

            setTimeout(() => {

                alert.remove();

            }, 500);

        });

    }, 5000);

});
