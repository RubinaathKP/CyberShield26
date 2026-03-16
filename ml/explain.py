import shap
import numpy as np


class ThreatExplainer:
    """
    SHAP-based explainability for host and network models.
    Generates per-prediction feature attributions for dashboard display.
    """

    def __init__(self, host_rf, net_rf, host_cols, net_cols):
        self.host_explainer = shap.TreeExplainer(host_rf)
        self.net_explainer  = shap.TreeExplainer(net_rf)
        self.host_cols = host_cols
        self.net_cols  = net_cols

    def explain_host(self, x_host_scaled):
        """
        x_host_scaled: 1D numpy array of scaled host features.
        Returns: list of {feature, shap_value, feature_value} dicts,
                 sorted by absolute SHAP value descending.
        """
        shap_vals = self.host_explainer.shap_values(x_host_scaled.reshape(1, -1))
        # shap_values returns list [benign_shap, attack_shap] for RF
        attack_shap = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0]

        result = []
        for feat, sv, fv in zip(self.host_cols, attack_shap, x_host_scaled):
            result.append({
                'feature':       feat,
                'shap_value':    round(float(sv), 4),
                'feature_value': round(float(fv), 4),
            })

        result.sort(key=lambda x: abs(x['shap_value']), reverse=True)
        return result

    def explain_network(self, x_net_scaled):
        """
        x_net_scaled: 1D numpy array of scaled network features.
        Returns: list of {feature, shap_value, feature_value} dicts.
        """
        shap_vals = self.net_explainer.shap_values(x_net_scaled.reshape(1, -1))
        attack_shap = shap_vals[1][0] if isinstance(shap_vals, list) else shap_vals[0]

        result = []
        for feat, sv, fv in zip(self.net_cols, attack_shap, x_net_scaled):
            result.append({
                'feature':       feat,
                'shap_value':    round(float(sv), 4),
                'feature_value': round(float(fv), 4),
            })
        result.sort(key=lambda x: abs(x['shap_value']), reverse=True)
        return result

    def explain_meta(self, p_host, p_network):
        """
        Simple linear attribution for the meta-classifier (SGDClassifier).
        Returns contribution of each base model to the final threat score.
        """
        return [
            {
                'feature':      'host_model_probability',
                'contribution': round(p_host, 4),
            },
            {
                'feature':      'network_model_probability',
                'contribution': round(p_network, 4),
            },
        ]
