
"""Generate a noisy sine wave, fit linear and SVM regressors, and visualize the results."""

import pathlib
import matplotlib
# Use a non-interactive backend so the script works in headless environments.
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error
from sklearn.svm import SVR


def generate_sine_wave(num_points: int = 200, noise_std: float = 0.2, random_state: int = 42):
    """Generate a sine wave and a noisy observation of it."""
    rng = np.random.default_rng(random_state)
    x = np.linspace(0, 2 * np.pi, num_points)
    y_true = np.sin(x)
    noise = rng.normal(0.0, noise_std, size=num_points)
    y_noisy = y_true + noise
    return x, y_true, y_noisy


def fit_models(x: np.ndarray, y: np.ndarray):
    """Fit linear regression and SVM regression models."""
    x_reshaped = x.reshape(-1, 1)

    linear_model = LinearRegression()
    linear_model.fit(x_reshaped, y)
    linear_predictions = linear_model.predict(x_reshaped)

    svm_model = SVR(kernel="rbf", C=100, gamma=0.1, epsilon=0.1)
    svm_model.fit(x_reshaped, y)
    svm_predictions = svm_model.predict(x_reshaped)

    return linear_model, svm_model, linear_predictions, svm_predictions


def plot_results(x, y_true, y_noisy, linear_predictions, svm_predictions, output_path: pathlib.Path):
    """Create plots comparing the noisy data and model predictions."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5), sharex=True)

    axes[0].plot(x, y_true, label="Gerçek sinüs", color="black", linewidth=2)
    axes[0].scatter(x, y_noisy, label="Gürültülü veri", color="tab:blue", s=15, alpha=0.7)
    axes[0].set_title("Sinüs Dalgası ve Gürültülü Ölçümler")
    axes[0].set_xlabel("x")
    axes[0].set_ylabel("y")
    axes[0].legend()

    axes[1].plot(x, y_true, label="Gerçek sinüs", color="black", linewidth=2)
    axes[1].scatter(x, y_noisy, label="Gürültülü veri", color="tab:blue", s=15, alpha=0.5)
    axes[1].plot(x, linear_predictions, label="Lineer Regresyon", color="tab:orange", linewidth=2)
    axes[1].plot(x, svm_predictions, label="SVR", color="tab:green", linewidth=2)
    axes[1].set_title("Model Tahminleri")
    axes[1].set_xlabel("x")
    axes[1].set_ylabel("y")
    axes[1].legend()

    fig.suptitle("Gürültülü Sinüs Dalgası Tahmini")
    fig.tight_layout(rect=[0, 0, 1, 0.96])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path)
    plt.close(fig)


def main():
    x, y_true, y_noisy = generate_sine_wave()
    linear_model, svm_model, linear_predictions, svm_predictions = fit_models(x, y_noisy)

    linear_mse = mean_squared_error(y_true, linear_predictions)
    svm_mse = mean_squared_error(y_true, svm_predictions)

    output_path = pathlib.Path("figures/sine_regression.png")
    plot_results(x, y_true, y_noisy, linear_predictions, svm_predictions, output_path)

    print("Lineer Regresyon MSE:", round(linear_mse, 4))
    print("SVR MSE:", round(svm_mse, 4))
    print(f"Grafik kaydedildi: {output_path}")


if __name__ == "__main__":
    main()
