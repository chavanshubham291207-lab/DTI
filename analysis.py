"""
GREEN GRID - Rule-Based Environmental Analysis Engine
Provides transparent, deterministic ecological risk assessment,
rule-based recommendations, and 3D visualization scene parameters.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Thresholds configurable via Environment variables
CONFIG = {
    "POLLUTION_HIGH_THRESHOLD": float(os.getenv("POLLUTION_HIGH_THRESHOLD", 150.0)),
    "POLLUTION_MODERATE_THRESHOLD": float(os.getenv("POLLUTION_MODERATE_THRESHOLD", 100.0)),
    "GREEN_COVER_LOW_THRESHOLD": float(os.getenv("GREEN_COVER_LOW_THRESHOLD", 25.0)),
    "GREEN_COVER_HIGH_THRESHOLD": float(os.getenv("GREEN_COVER_HIGH_THRESHOLD", 45.0)),
}


def calculate_risk(pollution_index: float, green_cover_pct: float) -> dict:
    """
    Deterministically computes urban environmental risk from pollution indicator and green cover %.
    
    Returns a dictionary containing:
    - score: Vulnerability Index (0-100)
    - risk_level: 'HIGH' | 'MEDIUM' | 'LOW'
    - risk_color: '#ef4444' | '#f59e0b' | '#10b981'
    - explanation: Clear, human-readable rationale
    - sub_scores: { pollution_score, green_deficit_score }
    - three_params: Parameters dynamically controlling 3D City Block preview
    - recommendations: Rule-matched actionable interventions
    """
    # 1. Component calculations
    # Pollution component: normalized against AQI 300 scale
    pollution_component = min(100.0, max(0.0, (pollution_index / 300.0) * 100.0))
    # Green deficit component: 100% when green cover is 0%, 0% when green cover >= 50%
    green_deficit_component = max(0.0, min(100.0, 100.0 - (green_cover_pct * 2.0)))

    # Weighted vulnerability score: 60% air pollution impact + 40% vegetative buffer deficit
    score = round(0.60 * pollution_component + 0.40 * green_deficit_component, 1)

    p_high = CONFIG["POLLUTION_HIGH_THRESHOLD"]
    p_mod = CONFIG["POLLUTION_MODERATE_THRESHOLD"]
    g_low = CONFIG["GREEN_COVER_LOW_THRESHOLD"]

    is_high_pollution = pollution_index >= p_high
    is_mod_pollution = pollution_index >= p_mod
    is_low_green = green_cover_pct < g_low

    # 2. Risk Level Assignment
    if is_high_pollution and is_low_green:
        risk_level = "HIGH"
        risk_color = "#dc2626"
        explanation = (
            f"Compounded high-risk environment: Pollution index of {pollution_index} exceeds the critical "
            f"threshold ({p_high}), combined with an acute green canopy deficit ({green_cover_pct}% vs minimum target {g_low}%). "
            f"Urban heat island effect and particulate entrapment are substantially amplified."
        )
    elif is_high_pollution:
        risk_level = "HIGH"
        risk_color = "#dc2626"
        explanation = (
            f"Elevated emission stress: Severe pollution index ({pollution_index} > {p_high}) detected despite "
            f"canopy coverage of {green_cover_pct}%. Indicates severe vehicular or point-source industrial emissions "
            f"overwhelming natural absorption capacities."
        )
    elif is_low_green and is_mod_pollution:
        risk_level = "MEDIUM"
        risk_color = "#d97706"
        explanation = (
            f"Moderate vulnerability: Marginal green canopy ({green_cover_pct}% < {g_low}%) with moderate air pollution "
            f"({pollution_index}). Lack of natural vegetative buffering exposes the area to sudden thermal spikes "
            f"and runoff degradation."
        )
    elif is_low_green:
        risk_level = "MEDIUM"
        risk_color = "#d97706"
        explanation = (
            f"Canopy deficit warning: Pollution indicator ({pollution_index}) is within baseline safety, but green cover "
            f"({green_cover_pct}%) is critically below the {g_low}% urban threshold. Susceptible to long-term micro-climate warming."
        )
    elif is_mod_pollution:
        risk_level = "MEDIUM"
        risk_color = "#d97706"
        explanation = (
            f"Transitional state: Pollution is elevated ({pollution_index}), but healthy vegetation buffer ({green_cover_pct}%) "
            f"actively mitigates heat and particulate dispersion. Active traffic calming required."
        )
    else:
        risk_level = "LOW"
        risk_color = "#059669"
        explanation = (
            f"Ecological equilibrium: Pollution index ({pollution_index}) is well controlled and green cover "
            f"({green_cover_pct}%) meets urban sustainability benchmarks. Focus remains on conservation and continuous telemetry."
        )

    # 3. Dynamic 3D Scene Parameters
    # Higher pollution -> denser fog, brownish/grey haze, darker sky
    # Higher green cover -> greener terrain, higher tree count
    fog_density = round(0.008 + (pollution_index / 500.0) * 0.055, 4)
    if pollution_index > 200:
        fog_color = "#7c6f5a"
        sky_color = "#616870"
    elif pollution_index > 100:
        fog_color = "#9ca3af"
        sky_color = "#788796"
    else:
        fog_color = "#c7d2fe"
        sky_color = "#93c5fd"

    tree_count = max(4, min(36, int((green_cover_pct / 100.0) * 36)))
    
    # Ground color interpolates from yellowish-dry to deep forest green
    green_factor = min(1.0, green_cover_pct / 50.0)
    ground_color = f"#{int(0x4a - (0x1a * green_factor)):02x}{int(0x5a + (0x3a * green_factor)):02x}{int(0x30 + (0x18 * green_factor)):02x}"

    three_params = {
        "fog_density": fog_density,
        "fog_color": fog_color,
        "sky_color": sky_color,
        "tree_count": tree_count,
        "ground_color": ground_color,
        "pollution_index": pollution_index,
        "green_cover_pct": green_cover_pct,
        "risk_level": risk_level,
    }

    # 4. Tailored Actionable Recommendations
    recommendations = []
    if is_high_pollution and is_low_green:
        recommendations.append({
            "category": "Integrated Intervention",
            "title": "Emergency Low-Emission Zone & Micro-Forest Network",
            "description": "Establish a combined commercial transport restriction corridor and rapidly deploy Miyawaki high-density urban forests along major transit arteries to scrub particulates.",
            "priority": "HIGH",
            "estimated_cost": "₹3.8 Cr",
            "time_horizon": "6-12 Months",
            "target_metric": "Reduce PM2.5 by 28%, increase canopy by 15%",
        })
    
    if is_high_pollution:
        recommendations.append({
            "category": "Emissions & Transit",
            "title": "Industrial Stack Audits & Feeder Bus Electrification",
            "description": "Mandate continuous stack telemetry for local fabrication units and convert arterial diesel feeder buses to zero-emission electric shuttles.",
            "priority": "HIGH",
            "estimated_cost": "₹2.2 Cr",
            "time_horizon": "3-6 Months",
            "target_metric": "Cut peak rush-hour AQI surges by 35 points",
        })

    if is_low_green:
        recommendations.append({
            "category": "Urban Forestry",
            "title": "Native Canopy Reforestation & Green Roof Mandates",
            "description": "Plant indigenous drought-resilient trees (Neem, Peepal, Banyan) across public rights-of-way and subsidize extensive green roofs on municipal buildings.",
            "priority": "HIGH" if risk_level == "HIGH" else "MEDIUM",
            "estimated_cost": "₹1.5 Cr",
            "time_horizon": "6-18 Months",
            "target_metric": "Boost ward canopy coverage to >= 30%",
        })

    if risk_level == "MEDIUM" and not is_high_pollution and not is_low_green:
        recommendations.append({
            "category": "Traffic & Microclimate",
            "title": "Traffic Calming & Permeable Pavement Installation",
            "description": "Install synchronized smart signals to reduce idling emissions and replace impermeable road medians with porous bio-swales.",
            "priority": "MEDIUM",
            "estimated_cost": "₹85 Lakhs",
            "time_horizon": "3-9 Months",
            "target_metric": "Improve storm infiltration & lower localized VOCs",
        })

    if risk_level == "LOW":
        recommendations.append({
            "category": "Conservation & Telemetry",
            "title": "Continuous Sensor Densification & Green Belt Preservation",
            "description": "Safeguard existing high-canopy woodlands against commercial rezoning and expand IoT ambient air sensor grid by 4 micro-nodes.",
            "priority": "LOW",
            "estimated_cost": "₹35 Lakhs",
            "time_horizon": "Ongoing Maintenance",
            "target_metric": "Maintain ecological equilibrium within WHO guidelines",
        })

    return {
        "score": score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "explanation": explanation,
        "sub_scores": {
            "pollution_component": round(pollution_component, 1),
            "green_deficit_component": round(green_deficit_component, 1),
        },
        "three_params": three_params,
        "recommendations": recommendations,
    }


# Alias to satisfy analyze() function requirement without changing rules
analyze = calculate_risk
