"""File for tests."""

sample_vehicle = {
    "vehicles": [
        {
            "vin": "vin",
            "dateOfSale": "2024-12-29",
            "primaryUser": True,
            "make": "make",
            "model": "model",
            "year": "2024",
            "exteriorColorCode": "exteriorColorCode",
            "exteriorColor": "exteriorColor",
            "simState": "simState",
            "modelDescription": "modelDescription",
            "country": "country",
            "region": "region",
            "alphaThreeCountryCode": "alphaThreeCountryCode",
            "countryName": "countryName",
            "isFleet": False,
        }
    ]
}
sample_vehicle_state = {
    "vin": "1234567890ABCDEFG",
    "ts": "2024-03-14T12:34:56.789Z",
    "state": {
        "extLocMap": {"lon": 123.456, "lat": 456.789, "ts": "1678886400000"},
        "cst": "1",
        "tuState": "1",
        "ods": "0",
        "ignitionState": "0",
        "odo": [{"2025-02-09 15:14:49": "1223"}, {"2025-02-10 20:54:33": "1242"}],
        "theftAlarm": "OFF",
        "svla": "0",
        "svtb": "0",
        "diagnostic": "0",
        "privacy": "0",
        "temp": "1",
        "factoryReset": "0",
        "tuStateTS": "1739934731691",
        "ignitionStateTs": "1739913349354",
        "timezone": "UTC",
        "accessible": True,
        "chargingControl": {
            "cruisingRangeCombined": "200",
            "eventTimestamp": "1678886400000",
        },
    },
}

sample_remote_operaton_response = {
    "eventId": "59668d8a-6426-4691-b61b-3c87d206d3f9",
    "statusTimestamp": "2024-03-14T12:34:56.789Z",
    "startTime": "2024-03-14T12:34:56.789Z",
    "operationType": "engineOff",
    "vin": "1234567890ABCDEFG",
    "state": "1",
    "status": "success",
}


sample_vehicle_status = {
    "vhr": [
        {
            "cid": "a7ddec3e-575f-4ea4-9038-c1692caecac2",
            "vin": "1234567890ABCDEFG",
            "operation": "vehicleStatus",
            "ts": 1739934753,
            "dt": {
                "diagnostic": {
                    "breakWarn": {
                        "name": "Brake Warning",
                        "displayMessage": "break_good",
                        "value": "0",
                        "warning": False,
                    },
                    "odos": {
                        "name": "Mileage Unit",
                        "displayMessage": "odos_miles",
                        "value": "0",
                    },
                    "engineOilWarn": {
                        "name": "Engine Oil Pressure",
                        "displayMessage": "engineOil_good",
                        "value": "0",
                        "warning": False,
                    },
                    "digsts": "1739934741242",
                    "tireStatus": {
                        "name": "TPMS Warning",
                        "displayMessage": "tirepressure_adequately",
                        "value": "0",
                        "warning": False,
                    },
                    "availRange": {
                        "name": "Available Range",
                        "displayMessage": "availRange_miles",
                        "value": "--",
                    },
                    "odo": {
                        "name": "Mileage",
                        "displayMessage": "odo_miles",
                        "value": "1447",
                    },
                    "spd": {
                        "name": "Vehicle Speed",
                        "displayMessage": "vehicle_speed",
                        "value": "0",
                    },
                    "igst": {
                        "name": "IG Status",
                        "displayMessage": "igst_off",
                        "value": "0",
                    },
                },
                "message": "SNAPSHOT",
                "vehicleStatus": {
                    "doorStatus": {
                        "id": "doorStatus",
                        "name": "Door Status",
                        "doors": [
                            {
                                "position": {
                                    "name": "Door Position",
                                    "displayMessage": "doorFrontLeft",
                                    "value": "0",
                                },
                                "state": {
                                    "name": "Door State",
                                    "displayMessage": "#msg_close_close",
                                    "value": "0",
                                },
                            },
                            {
                                "position": {
                                    "name": "Door Position",
                                    "displayMessage": "doorHood",
                                    "value": "1",
                                },
                                "state": {
                                    "name": "Door State",
                                    "displayMessage": "#msg_close_close",
                                    "value": "0",
                                },
                            },
                            {
                                "position": {
                                    "name": "Door Position",
                                    "displayMessage": "doorFrontRight",
                                    "value": "2",
                                },
                                "state": {
                                    "name": "Door State",
                                    "displayMessage": "#msg_close_close",
                                    "value": "0",
                                },
                            },
                            {
                                "position": {
                                    "name": "Door Position",
                                    "displayMessage": "doorRearLeft",
                                    "value": "3",
                                },
                                "state": {
                                    "name": "Door State",
                                    "displayMessage": "#msg_close_close",
                                    "value": "0",
                                },
                            },
                            {
                                "position": {
                                    "name": "Door Position",
                                    "displayMessage": "doorRearRight",
                                    "value": "4",
                                },
                                "state": {
                                    "name": "Door State",
                                    "displayMessage": "#msg_close_close",
                                    "value": "0",
                                },
                            },
                            {
                                "position": {
                                    "name": "Door Position",
                                    "displayMessage": "doorTrunk",
                                    "value": "5",
                                },
                                "state": {
                                    "name": "Door State",
                                    "displayMessage": "#msg_close_close",
                                    "value": "0",
                                },
                            },
                        ],
                    },
                    "lightStatus": {
                        "id": "lightStatus",
                        "name": "Lights Status",
                        "lights": [
                            {
                                "state": {
                                    "name": "Light State",
                                    "displayMessage": "#msg_off_off",
                                    "value": "3",
                                },
                                "position": {
                                    "name": "Light Position",
                                    "displayMessage": "lightHead",
                                    "value": "0",
                                },
                            }
                        ],
                    },
                },
            },
        }
    ]
}
