from jinja2 import Environment, FileSystemLoader


class PromelaGenerator:

    def __init__(self, template_dir: str, output_file: str) -> None:
        self.output_file = output_file
        env = Environment(loader=FileSystemLoader(template_dir))
        self.template = env.get_template("Templates/Template.pml")

    def Generate(self, DEVICE_NAME, DEVICE_RESOURCES, DEVICE_POLICIES):
        result = self.template.render(Resources=DEVICE_RESOURCES,
                                      DefaultPolicies=DEVICE_POLICIES["default"]["Policies"],
                                      Configurations=DEVICE_POLICIES["Configurations"])
        with open(self.output_file, "w", encoding='UTF-8') as f:
            f.write(result)
