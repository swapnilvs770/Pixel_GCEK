document.addEventListener("DOMContentLoaded", function () {
    const themeToggle = document.getElementById("theme-toggle");
    const logo = document.getElementById("logo");
    const heroVideo = document.querySelector(".hero-video");
    const backToTopButton = document.getElementById("back-to-top");
    const galleryContainer = document.querySelector(".gallery");
    const seeMoreButton = document.getElementById("see-more");

    // Theme Toggle
    // Select theme toggle button only onc

    // Function to update the logo (if it exists in the HTML)
    function updateLogo() {
        const logo = document.getElementById("logo");
        if (!logo) return;

        logo.style.transition = "opacity 0.25s ease-out, transform 0.25s ease-out";
        logo.style.opacity = "0";
        logo.style.transform = "scale(0.9)";

        setTimeout(() => {
            logo.src = document.body.classList.contains("dark-mode")
                ? "static/images/logo-white.png"
                : "static/images/logo-black.png";

            logo.style.opacity = "1";
            logo.style.transform = "scale(1)";
        }, 250);
    }

    // Apply theme from localStorage on page load
    if (localStorage.getItem("theme") === "dark") {
        document.body.classList.add("dark-mode");
        themeToggle.textContent = "☀️";
    } else {
        document.body.classList.remove("dark-mode");
        themeToggle.textContent = "🌙";
    }

    // Event listener for theme toggle
    themeToggle.addEventListener("click", () => {
        document.body.classList.toggle("dark-mode");
        const isDarkMode = document.body.classList.contains("dark-mode");

        localStorage.setItem("theme", isDarkMode ? "dark" : "light");
        themeToggle.textContent = isDarkMode ? "☀️" : "🌙";

        updateLogo(); // Updates logo only if it exists
    });




    // Lightbox for Gallery with Navigation
    const galleryImages = document.querySelectorAll(".gallery img");
    const lightbox = document.createElement("div");
    lightbox.id = "lightbox";
    document.body.appendChild(lightbox);

    const img = document.createElement("img");
    lightbox.appendChild(img);

    const prevButton = document.createElement("button");
    prevButton.innerHTML = "&#10094;";
    prevButton.classList.add("lightbox-btn", "left");
    lightbox.appendChild(prevButton);

    const nextButton = document.createElement("button");
    nextButton.innerHTML = "&#10095;";
    nextButton.classList.add("lightbox-btn", "right");
    lightbox.appendChild(nextButton);

    let currentIndex = 0;

    function updateLightbox(index) {
        if (index >= 0 && index < galleryImages.length) {
            img.src = galleryImages[index].src;
            currentIndex = index;
        }
    }

    galleryImages.forEach((image, index) => {
        image.setAttribute("loading", "lazy");
        image.addEventListener("click", () => {
            lightbox.classList.add("active");
            updateLightbox(index);
        });
    });

    prevButton.addEventListener("click", () => {
        updateLightbox(currentIndex - 1);
    });

    nextButton.addEventListener("click", () => {
        updateLightbox(currentIndex + 1);
    });

    lightbox.addEventListener("click", (e) => {
        if (e.target !== img && e.target !== prevButton && e.target !== nextButton) {
            lightbox.classList.remove("active");
        }
    });

    // Keyboard Navigation
    document.addEventListener("keydown", (e) => {
        if (lightbox.classList.contains("active")) {
            if (e.key === "ArrowLeft") updateLightbox(currentIndex - 1);
            else if (e.key === "ArrowRight") updateLightbox(currentIndex + 1);
            else if (e.key === "Escape") lightbox.classList.remove("active");
        }
    });

    // Back to Top Button
    window.addEventListener("scroll", () => {
        backToTopButton.style.display = window.scrollY > 300 ? "block" : "none";
    });

    backToTopButton.addEventListener("click", () => {
        window.scrollTo({ top: 0, behavior: "smooth" });
    });

    // Horizontal Scroll for Gallery
    galleryContainer.addEventListener("wheel", (e) => {
        e.preventDefault();
        galleryContainer.scrollLeft += e.deltaY;
    });

    // Smooth Scroll to Sections
    const galleryLink = document.querySelector('a[href="#gallery"]');
    if (galleryLink) {
        galleryLink.addEventListener("click", function (e) {
            e.preventDefault();
            document.querySelector("#gallery").scrollIntoView({ behavior: "smooth" });
        });
    }

    const teamLink = document.querySelector('a[href="#team"]');
    if (teamLink) {
        teamLink.addEventListener("click", function (e) {
            e.preventDefault();
            document.querySelector("#team").scrollIntoView({ behavior: "smooth" });
        });
    }

    // Open New Page for See More Button
    document.getElementById("see-more").addEventListener("click", () => {
        window.open("gallery.html", "_blank"); // Opens the gallery page in a new tab
    });

});